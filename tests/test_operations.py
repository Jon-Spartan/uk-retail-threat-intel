import sqlite3
import subprocess
import sys
import unittest
from contextlib import closing
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests

import delivery
import feed_transport
from operations import assign_identity, canonical_article_url, collection_lock, deduplicate, due_briefing


class OperationalTests(unittest.TestCase):
    def test_tracking_variants_share_identity_but_distinct_urls_stay_distinct(self):
        variant = "https://EXAMPLE.invalid:443/report?utm_source=mail&id=4&lang=en#heading"
        url = canonical_article_url(variant)
        self.assertEqual(url, "https://example.invalid/report?id=4&lang=en")
        seen = "2026-01-01T08:00:00+00:00"
        first = assign_identity({"source": "Feed A", "title": "First title"}, url, seen)
        second = assign_identity({"source": "Feed B", "title": "Updated title"}, canonical_article_url(variant), seen)
        self.assertEqual(first["id"], second["id"])
        articles = deduplicate([first.copy(), second.copy()])
        self.assertEqual(articles, deduplicate([second.copy(), first.copy()]))
        self.assertEqual(articles[0]["source_ids"], ["feed-a", "feed-b"])
        for other in ("https://example.invalid/report?id=5&lang=en",
                      "https://example.invalid/reprints/report?id=4&lang=en",
                      "https://other.example.invalid/report?id=4&lang=en"):
            self.assertNotEqual(assign_identity({"source": "Feed C"}, other, seen)["id"], first["id"])

    def test_london_slots_catch_up_after_expected_time_and_follow_dst(self):
        def when(stamp):
            return datetime.fromisoformat(stamp + "+00:00")

        for before, after in (("2026-01-05T07:14", "2026-01-05T11:03"),
                              ("2026-07-06T06:14", "2026-07-06T06:15")):
            self.assertFalse(due_briefing("daily", {}, when(before)))
            self.assertTrue(due_briefing("daily", {}, when(after)))
            self.assertFalse(due_briefing("daily", {"daily": {"checked_at": when(after).isoformat()}}, when(after)))
        self.assertFalse(due_briefing("daily", {}, when("2026-07-04T10:00")))
        self.assertFalse(due_briefing("weekly", {}, when("2026-07-03T14:59")))
        self.assertTrue(due_briefing("weekly", {}, when("2026-07-03T15:00")))
        saturday = when("2026-07-04T12:00")
        self.assertTrue(due_briefing("weekly", {}, saturday))
        self.assertFalse(due_briefing("weekly", {"weekly": {"checked_at": "2026-07-03T17:00+00:00"}}, saturday))
        self.assertFalse(due_briefing("weekly", {}, when("2026-07-06T08:00")))

    def test_collection_lock_rejects_an_overlapping_process_and_releases(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / ".lock"
            code = ("from pathlib import Path; from operations import collection_lock\n"
                    "with collection_lock(Path(__import__('sys').argv[1])) as lock: print(lock)")
            with collection_lock(path) as acquired:
                self.assertTrue(acquired)
                other = subprocess.check_output([sys.executable, "-B", "-c", code, str(path)], text=True)
                self.assertEqual(other.strip(), "False")
            with collection_lock(path) as acquired:
                self.assertTrue(acquired)

    def test_feed_download_bounds_and_rejects_redirects_outside_source(self):
        with patch.object(feed_transport, "FeedSession") as factory:
            session = factory.return_value.__enter__.return_value
            response = session.get.return_value.__enter__.return_value
            response.status_code = 200
            response.headers = {}
            response.iter_content.return_value = [b"123", b"456"]
            with self.assertRaisesRegex(feed_transport.FeedError, "size limit"):
                feed_transport.download_source("https://example.invalid/feed", limit=5)
            self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
            self.assertFalse(session.trust_env)
            response.status_code = 302
            response.headers = {"Location": "https://other.example.invalid/feed"}
            with self.assertRaisesRegex(feed_transport.FeedError, "outside the allowed hosts"):
                feed_transport.download_source("https://example.invalid/feed")
            redirect, final = MagicMock(), MagicMock()
            redirect.__enter__.return_value.status_code = 301
            redirect.__enter__.return_value.headers = {"Location": "https://www.example.invalid/feed"}
            final.__enter__.return_value = response
            response.status_code = 200
            response.headers = {}
            session.get.side_effect = [redirect, final]
            self.assertEqual(feed_transport.download_source("https://example.invalid/feed"), b"123456")


class OutboxTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "notifications.sqlite3"
        self.webhook = "https://webhook.example.invalid/private-marker"
        self.now = 1000
        self.event = ("flash:report", "Fixture notification", 4000)

    def send(self, events=(), webhook=None, legacy=None):
        destination = webhook or self.webhook
        delivery.queue_outbox(self.path, destination, events, self.now, legacy=legacy)
        delivery.deliver_outbox(self.path, destination, clock=lambda: self.now)

    def states(self):
        with closing(sqlite3.connect(self.path)) as database:
            return database.execute("SELECT state,attempts FROM deliveries ORDER BY attempts DESC").fetchall()

    def test_429_respects_delay_and_retries_even_after_source_disappears(self):
        with patch.object(delivery.requests, "post", side_effect=[
            SimpleNamespace(status_code=429, headers={"Retry-After": "120"}),
            SimpleNamespace(status_code=204),
            SimpleNamespace(status_code=204),
        ]) as post, self.assertLogs(level="WARNING") as logs:
            self.send([self.event])
            self.now += 119
            self.send()
            self.assertEqual(self.states(), [("queued", 1)])
            self.now += 1
            self.send()
            self.send([self.event])
            self.assertEqual(self.states(), [("sent", 2)])
            self.send([self.event], webhook="https://other.example.invalid/")
            self.assertEqual(self.states(), [("sent", 2), ("sent", 1)])
        self.assertEqual(post.call_count, 3)
        self.assertTrue(all(not call.kwargs["allow_redirects"] for call in post.call_args_list))
        self.assertNotIn("private-marker", str(logs.output))
        self.assertNotIn(self.webhook.encode(), self.path.read_bytes())

    def test_ambiguous_response_and_interrupted_delivery_are_never_automatically_retried(self):
        interrupted = ("daily:slot", "Fixture briefing", 4000)
        with patch.object(delivery.requests, "post", side_effect=[
            SimpleNamespace(status_code=503), KeyboardInterrupt
        ]) as post:
            self.send([self.event])
            with self.assertRaises(KeyboardInterrupt):
                self.send([interrupted])
            self.now += 1000
            self.send([self.event, interrupted])
        self.assertEqual(post.call_count, 2)
        self.assertCountEqual(self.states(), [("uncertain", 1), ("sending", 1)])

    def test_legacy_acknowledgements_not_resent_and_connect_timeout_retries(self):
        legacy = lambda: ([self.event[0]], [("weekly:slot", "Legacy pending fixture", 4000)])
        with patch.object(delivery.requests, "post", side_effect=[
            requests.exceptions.ConnectTimeout, SimpleNamespace(status_code=204)
        ]) as post:
            self.send([self.event], legacy=legacy)
            self.now += 61
            self.send([self.event], legacy=legacy)
        self.assertEqual(post.call_count, 2)
        self.assertEqual(self.states(), [("sent", 2), ("sent", 0)])

    def test_claim_is_committed_before_the_webhook_request(self):
        def competing_dispatch(*args, **kwargs):
            self.send([self.event])
            return SimpleNamespace(status_code=204)

        with patch.object(delivery.requests, "post", side_effect=competing_dispatch) as post:
            self.send([self.event])
        post.assert_called_once()
        self.assertEqual(self.states(), [("sent", 1)])


if __name__ == "__main__":
    unittest.main()
