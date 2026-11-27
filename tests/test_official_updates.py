import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from feed_transport import FeedError
from official_updates import parse_stories, refresh_updates, validate_updates


NOW = datetime(2026, 11, 26, tzinfo=timezone.utc)
ARTICLE = "https://www.ncsc.gov.uk/news/public-statement"
ADVISORY = "https://www.cisa.gov/news-events/cybersecurity-advisories/advisory"
CERT_ADVISORY = "https://cert.europa.eu/publications/security-advisories/2026-022"


def rss(*items):
    body = "".join(
        f"<item><title>{title}</title><link>{url}</link><pubDate>{date}</pubDate>"
        "<description>Excluded body</description></item>" for title, url, date in items
    )
    return f'<rss version="2.0"><channel><title>Fixture</title>{body}</channel></rss>'.encode()


DATE = "Wed, 25 Nov 2026 12:00:00 GMT"


class OfficialUpdatesTests(unittest.TestCase):
    def test_publishes_dated_canonical_citations_only(self):
        records = parse_stories("ncsc", rss(
            ("Official release", ARTICLE, DATE),
            ("Canonical duplicate", ARTICLE + "?tracking=1", DATE),
            ("External link", "https://example.com/news/public-statement", DATE),
            ("Unapproved path", "https://www.ncsc.gov.uk/register/subscribe", DATE),
            ("Undated", "https://www.ncsc.gov.uk/news/undated", ""),
            ("&lt;img src=x&gt;", "https://www.ncsc.gov.uk/news/injected", DATE),
            ("Future", "https://www.ncsc.gov.uk/news/future", "Fri, 27 Nov 2026 00:00:00 GMT"),
        ), NOW)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["url"], ARTICLE)
        self.assertEqual(records[0]["title"], "Official release")
        self.assertEqual(set(records[0]), {"id", "source", "title", "url", "published_at"})
        cisa = rss(
            ("Advisory", ADVISORY, DATE),
            ("CISA adds to Known Exploited Vulnerabilities", ADVISORY + "-new", DATE),
        )
        self.assertEqual([record["url"] for record in parse_stories("cisa", cisa, NOW)], [ADVISORY])

    def test_unavailable_feed_retains_eligible_previous_headlines(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "official_updates.json"
            with patch("feed_transport.download_source", side_effect=[
                rss(("NCSC story", ARTICLE, DATE)), rss(("CISA story", ADVISORY, DATE)), rss(), rss(),
            ]):
                refresh_updates(path, NOW)
            previous = json.loads(path.read_text(encoding="utf-8"))
            with patch("feed_transport.download_source", side_effect=[FeedError("Unavailable"), b"<html/>", rss(), rss()]):
                refresh_updates(path, NOW + timedelta(minutes=15))
            retained = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(retained["stories"], previous["stories"])
            self.assertEqual(retained["sources"], {
                "ncsc": "unavailable", "cisa": "unavailable", "cert_eu_advisories": "current", "cert_eu_briefs": "current",
            })
            retained["stories"][0]["url"] = "https://example.com/other"
            with self.assertRaises(ValueError):
                validate_updates(retained)
            with patch("feed_transport.download_source", side_effect=[FeedError("Unavailable"), rss(), rss(), rss()]):
                refresh_updates(path, NOW + timedelta(days=31))
            expired = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(expired["stories"], [])
            self.assertEqual(expired["sources"], {
                "ncsc": "unavailable", "cisa": "current", "cert_eu_advisories": "current", "cert_eu_briefs": "current",
            })

    def test_first_collection_preserves_a_previous_snapshot_and_adds_dated_cert_eu_citations(self):
        earlier = {"checked_at": NOW.isoformat(), "sources": {"ncsc": "current", "cisa": "current"},
                   "stories": parse_stories("ncsc", rss(("Previous title", ARTICLE, DATE)), NOW)}
        with self.assertRaises(ValueError):
            validate_updates(earlier)
        validate_updates(earlier, restoring=True)
        body = rss(("Public advisory", f"\n  {CERT_ADVISORY}/\n", "Wed, 25 Nov 2026 22:00:00 CET"),
                   ("Wrong category", "https://cert.europa.eu/publications/threat-intelligence/cb26-11/", DATE),
                   ("Other publisher", "https://lookalike.example/publications/security-advisories/2026-022", DATE))
        brief = rss(("Monthly brief", "https://cert.europa.eu/publications/threat-intelligence/cb26-11/",
                     "Wed, 25 Nov 2026 20:00:00 CET"))
        with TemporaryDirectory() as directory:
            path = Path(directory) / "official_updates.json"
            path.write_text(json.dumps(earlier), encoding="utf-8")
            with patch("feed_transport.download_source", side_effect=[FeedError("Unavailable"), rss(), body, brief]):
                refresh_updates(path, NOW + timedelta(minutes=15))
            updated = json.loads(path.read_text(encoding="utf-8"))
            validate_updates(updated)
        self.assertEqual([item["source"] for item in updated["stories"]], ["cert_eu_advisories", "cert_eu_briefs", "ncsc"])
        self.assertEqual(updated["stories"][0]["url"], CERT_ADVISORY)
        self.assertEqual(updated["stories"][0]["published_at"], "2026-11-25T21:00:00+00:00")
