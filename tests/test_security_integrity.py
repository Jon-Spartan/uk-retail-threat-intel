import json
import os
import unittest
from contextlib import chdir
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from xml.etree import ElementTree

import threat_intel_pipeline as pipeline
from briefings import render_summary, snapshot_sources, utc_time
from classification import sanitize_archive


ARTICLE = {
    "id": "offline-record",
    "title": "Offline source article",
    "source": "Fixture",
    "summary": "Plain source excerpt",
    "url": "https://source.example.invalid/report?lang=en&view=full",
    "severity": "HIGH",
    "confidence": None,
    "is_flash": True,
}

def fixture_briefing(period, coverage="current"):
    stamp = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": 1, "period": period, "coverage": coverage,
        "generated_at": stamp, "validated_at": stamp,
        "sources": snapshot_sources([ARTICLE], period),
        "selection": {"facts": ["S01"], "assessments": [], "recommendations": []},
    }


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        data_dir = self.root / "work"
        data_dir.mkdir()
        self.enterContext(chdir(data_dir))
        self.enterContext(patch.dict(os.environ, {}, clear=True))

    def test_urls_and_source_report_export(self):
        for url in ("file:///tmp/report", "//example.invalid/report", "ftp://example.invalid",
                    "https://user@example.invalid", "https://example.invalid:zero", "https:///report"):
            with self.subTest(url=url):
                self.assertIsNone(pipeline.validated_http_url(url))
        self.assertEqual(pipeline.validated_http_url(ARTICLE["url"]), ARTICLE["url"])

        pipeline.export_stix_and_rss([ARTICLE, dict(ARTICLE, url="file:///tmp/report")])
        objects = json.loads(Path("data/threats.stix.json").read_text(encoding="utf-8"))["objects"]
        url, report = objects
        self.assertEqual([url["type"], report["type"]], ["url", "report"])
        self.assertEqual(report["object_refs"], [url["id"]])
        self.assertEqual(report["external_references"][0]["url"], ARTICLE["url"])
        self.assertNotIn("confidence", report)
        links = ElementTree.parse("data/feed.xml").findall("./channel/item/link")
        self.assertEqual([link.text for link in links], [ARTICLE["url"]])

    def test_failed_collection_preserves_snapshot_and_clears_flash(self):
        status = {}
        archive = [dict(ARTICLE)]
        sanitize_archive(archive)
        archive = pipeline.migrate_record_identity(archive, datetime.now(timezone.utc))
        pipeline.save_collection(archive, "partial", status)
        data = Path("data/threats.json").read_bytes()
        last_data_date = status["collection"]["data_updated_at"]
        pipeline.save_collection([], "failed", status)
        self.assertEqual(Path("data/threats.json").read_bytes(), data)
        self.assertEqual(status["collection"]["data_updated_at"], last_data_date)
        self.assertEqual(status["collection"]["state"], "failed")
        self.assertFalse(Path("data/flash_alert.json").exists())
        pipeline.save_collection([], "current", status)
        self.assertEqual(json.loads(Path("data/threats.json").read_bytes()), [])

    def test_collection_distinguishes_empty_valid_feed_and_parse_failure(self):
        sample = b"""<rss version="2.0"><channel><title>Fixture</title>
        <item><title>Retail fixture report</title>
        <link>https://source.example.invalid/report</link></item>
        <item><title>Retail fixture without web link</title>
        <link>file:///local/report</link></item></channel></rss>"""
        feed = {"name": "Fixture", "url": "https://source.example.invalid/feed", "subsector": "ecom"}
        with patch.object(pipeline, "FEEDS", [feed]), patch.object(pipeline, "fetch_cisa_kev_alerts") as kev, \
                patch.object(pipeline, "download_source") as get:
            kev.return_value = ([], set())
            get.return_value = sample
            records, status, health = pipeline.fetch_and_filter_intel()
            self.assertEqual(status, "current")
            self.assertEqual([record["url"] for record in records], ["https://source.example.invalid/report"])
            self.assertEqual(records[0]["classification"]["confidence"], "unassessed")
            stamp = health[1]["last_success_at"]
            get.return_value = b"<unusable-document>"
            retained, state, failed_health = pipeline.fetch_and_filter_intel(records, health)
            self.assertEqual(state, "partial")
            self.assertEqual(retained[0]["id"], records[0]["id"])
            self.assertTrue(retained[0]["carried_forward"])
            self.assertFalse(retained[0]["is_new"])
            self.assertEqual(failed_health[1]["last_success_at"], stamp)
            self.assertEqual(failed_health[1]["state"], "failed")
            self.assertEqual(failed_health[1]["items"], 0)
            kev.return_value = ([], None)
            self.assertEqual(pipeline.fetch_and_filter_intel()[:2], ([], "failed"))
            kev.return_value = ([], set())
            get.return_value = b'<rss version="2.0"><channel><title>Empty</title></channel></rss>'
            self.assertEqual(pipeline.fetch_and_filter_intel()[:2], ([], "current"))

    def test_briefing_failure_retains_explicitly_labelled_analysis(self):
        status = {}
        pipeline.save_collection([ARTICLE], "partial", status)
        document = fixture_briefing("daily", coverage="partial")
        with patch.object(pipeline, "generate_briefing", return_value=(document, "available")):
            pipeline.update_briefing([ARTICLE], "partial", status)
        path = Path("data/daily_summary.md")
        evidence = Path("data/daily_briefing.json")
        self.assertIn("Collection was incomplete.", path.read_text(encoding="utf-8"))
        previous_text = path.read_bytes()
        previous_evidence = evidence.read_bytes()
        generated_at = status["daily"]["generated_at"]
        validated_at = status["daily"]["validated_at"]
        pipeline.update_briefing([], "failed", status)
        self.assertEqual(path.read_bytes(), previous_text)
        self.assertEqual(evidence.read_bytes(), previous_evidence)
        self.assertEqual(status["daily"]["generated_at"], generated_at)
        self.assertEqual(status["daily"]["validated_at"], validated_at)
        self.assertEqual(status["daily"]["state"], "failed")
        self.assertEqual(pipeline.generate_briefing([], "weekly", "current"), (None, "unavailable"))

    def test_briefing_notifications_use_slot_identity_and_validate_evidence(self):
        Path("data").mkdir()
        for period in ("daily", "weekly"):
            with self.subTest(period=period):
                document = fixture_briefing(period)
                generated = utc_time(document["generated_at"])
                status = {period: {"state": "available", "generated_at": document["generated_at"],
                                   "validated_at": document["validated_at"]}}
                summary = Path(f"data/{period}_summary.md")
                summary.write_text(render_summary(document), encoding="utf-8")
                Path(f"data/{period}_briefing.json").write_text(json.dumps(document), encoding="utf-8")
                event, = pipeline.notification_events([], status, generated, (period,), False)
                self.assertEqual(event[0], f"{period}:{pipeline.notification_slot(period, generated)}")
                summary.write_text("Changed Markdown", encoding="utf-8")
                self.assertEqual(pipeline.notification_events([], status, generated, (period,), False), [])


if __name__ == "__main__":
    unittest.main()
