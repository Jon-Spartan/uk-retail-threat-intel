import os
import unittest
from contextlib import chdir
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import threat_intel_pipeline as pipeline
from briefings import kev_article_url
from scripts.publication import ASSETS, read_json, stage_site, validate_data, validate_release_data


ROOT = Path(__file__).resolve().parents[1]
ARTICLE_URL = "https://publisher.example.invalid/checkout"
CVE = "CVE-2024-12345"


class CollectionWorkflowTests(unittest.TestCase):
    def test_current_partial_and_failed_runs_preserve_feed_processing(self):
        feeds = [{"name": "RSS fixture", "url": "https://rss.example.invalid/feed"},
                 {"name": "Atom fixture", "url": "https://atom.example.invalid/feed"}]
        now = datetime.now(timezone.utc) - timedelta(minutes=10)
        payloads = {
            feeds[0]["url"]: f"""<rss version="2.0"><channel><title>Fixture</title>
              <item><title>Retail checkout fixture</title>
                <link>{ARTICLE_URL}?utm_source=fixture</link>
                <pubDate>{format_datetime(now)}</pubDate>
                <description><![CDATA[<p>Retail checkout &amp; payment</p>]]></description>
              </item>
              <item><title>Old retail fixture</title><link>{ARTICLE_URL}/old</link>
                <pubDate>{format_datetime(now - timedelta(days=9))}</pubDate>
              </item></channel></rss>""".encode(),
            feeds[1]["url"]: f"""<feed xmlns="http://www.w3.org/2005/Atom">
              <title>Fixture</title><id>urn:fixture:atom</id>
              <entry><title>Retail checkout fixture (Atom)</title><link href="{ARTICLE_URL}"/>
                <id>urn:fixture:report</id><updated>{now.isoformat()}</updated>
                <summary>Retail checkout fixture</summary></entry></feed>""".encode(),
        }

        def download_feed(url, **_):
            return payloads[url]

        with TemporaryDirectory() as directory, chdir(directory), \
                patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "WEBHOOK_URL": "https://fixture.example.invalid/",
                                        "RUN_MODE": "flash"}, clear=True), \
                patch.object(pipeline, "FEEDS", feeds), \
                patch.object(pipeline, "download_source", side_effect=download_feed), \
                patch.object(pipeline, "download_json", return_value={"vulnerabilities": []}) as json_source, \
                patch.object(pipeline, "deliver_outbox") as notify, \
                patch.object(pipeline, "generate_briefing") as generate:
            data = Path("data")
            pipeline.run_collection()
            validate_data(data)
            first = read_json(data / "threats.json")
            current = read_json(data / "intelligence_status.json")["collection"]
            self.assertEqual(current["state"], "current")
            self.assertEqual(len(first), 1)
            self.assertEqual(first[0]["url"], ARTICLE_URL)
            self.assertEqual(first[0]["source_ids"], ["atom-fixture", "rss-fixture"])
            self.assertTrue(first[0]["is_new"])
            self.assertEqual(first[0]["cves"], [])
            self.assertEqual(first[0]["classification"]["exploitation"], "unknown")

            payloads.update({url: b"<unparseable>" for url in payloads})
            pipeline.run_collection()
            validate_data(data)
            partial = read_json(data / "intelligence_status.json")["collection"]
            second = read_json(data / "threats.json")
            self.assertEqual(partial["state"], "partial")
            self.assertEqual(partial["last_success_at"], current["last_success_at"])
            self.assertEqual(second[0]["id"], first[0]["id"])
            self.assertTrue(second[0]["carried_forward"])
            self.assertFalse(second[0]["is_new"])
            self.assertFalse(second[0]["is_flash"])
            objects = read_json(data / "threats.stix.json")["objects"]
            self.assertCountEqual([obj["type"] for obj in objects], ["url", "report"])
            self.assertEqual(next(obj["value"] for obj in objects if obj["type"] == "url"), ARTICLE_URL)

            with self.assertRaisesRegex(ValueError, "outside the release policy"):
                stage_site(data, Path("staged-site"), ROOT)
            before_failure = {name: (data / name).read_bytes() for name in
                              ("threats.json", "threats.stix.json", "feed.xml")}
            json_source.return_value = {"invalid": "catalogue"}
            pipeline.run_collection()
            validate_data(data)
            failed = read_json(data / "intelligence_status.json")["collection"]
            self.assertEqual(failed["state"], "failed")
            self.assertEqual(failed["last_success_at"], current["last_success_at"])
            self.assertEqual(failed["data_updated_at"], partial["data_updated_at"])
            self.assertTrue(all((data / name).read_bytes() == value for name, value in before_failure.items()))
            notify.assert_not_called()
            generate.assert_not_called()

    def test_default_collection_and_staging_use_only_approved_sources(self):
        now = datetime.now(timezone.utc) - timedelta(hours=1)
        fixture = {"vulnerabilities": [{"cveID": CVE, "dateAdded": now.date().isoformat()}]}
        with TemporaryDirectory() as directory, chdir(directory), \
                patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUN_MODE": "flash"}, clear=True), \
                patch.object(pipeline, "download_json", return_value=fixture), \
                patch.object(pipeline, "load_vulnerability_evidence", return_value=({}, {})), \
                patch.object(pipeline, "download_source") as publisher_feed:
            pipeline.run_collection()
            data = Path("data")
            files = validate_release_data(data)
            records = read_json(data / "threats.json")
            self.assertEqual([record["url"] for record in records], [kev_article_url(CVE)])
            stage_site(data, Path("staged-site"), ROOT)
            public = {file.relative_to("staged-site").as_posix()
                      for file in Path("staged-site").rglob("*") if file.is_file()}
            self.assertEqual(public, set(ASSETS) | {f"data/{name}" for name in files})
            publisher_feed.assert_not_called()

    def test_kev_uses_valid_dated_entries_and_keeps_historical_membership(self):
        now = datetime(2026, 11, 25, 12, tzinfo=timezone.utc)
        expected = kev_article_url(CVE)
        mock = {"vulnerabilities": [
            {"cveID": CVE.lower(), "dateAdded": "2026-11-25"},
            {"cveID": "CVE-2024-12346", "dateAdded": "2026-01-01"},
            {"cveID": "CVE-2024-12347", "dateAdded": "2026-11-26"},
            {"cveID": "CVE-1900-0001", "dateAdded": "2026-11-25"},
            {"cveID": "not-a-cve", "dateAdded": "2026-11-25"},
        ]}
        with patch.object(pipeline, "download_json", return_value=mock):
            articles, catalogue = pipeline.fetch_cisa_kev_alerts(now - timedelta(days=7), {expected}, now)
        self.assertEqual(catalogue, {CVE, "CVE-2024-12346"})
        self.assertEqual([article["url"] for article in articles], [expected])
        self.assertFalse(articles[0]["is_new"])


if __name__ == "__main__":
    unittest.main()
