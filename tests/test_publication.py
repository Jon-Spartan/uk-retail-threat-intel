import json
import sys
from contextlib import chdir
from datetime import datetime, timezone
import unittest
from pathlib import Path
from shutil import copytree
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts import publication
from briefings import KEV_PUBLISHER, kev_article_url, render_summary, snapshot_sources
import threat_intel_pipeline as collector
from classification import classify_record, sanitize_archive
from operations import assign_identity


ROOT = Path(__file__).resolve().parents[1]


class PublicationTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.data = self.folder / "data"
        copytree(ROOT / "data", self.data)
        cve = "CVE-2024-12345"
        now = datetime.now(timezone.utc)
        record = assign_identity({"source": KEV_PUBLISHER, "title": "Offline catalogue fixture",
                                  "summary": "Offline catalogue fixture summary", "reported_cves": [cve]},
                                 kev_article_url(cve), now.isoformat())
        self.records = [record]
        sanitize_archive(self.records)
        classify_record(record, {cve}, {}, {}, now)
        self.write_records(self.records, now)

    def write_records(self, records, built_at=None):
        collector.write_json(self.data / "threats.json", records)
        with chdir(self.folder):
            collector.export_stix_and_rss(records, built_at=built_at)

    def change_json(self, name, transform):
        path = self.data / name
        value = json.loads(path.read_text(encoding="utf-8"))
        transform(value)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_staged_site_contains_only_manifest_files(self):
        site = self.folder / "site"
        publication.stage_site(self.data, site, ROOT)
        expected = set(publication.ASSETS)
        expected.add("site_status.json")
        expected.update(f"data/{path.name}" for path in self.data.iterdir())
        actual = {path.relative_to(site).as_posix() for path in site.rglob("*") if path.is_file()}
        self.assertEqual(actual, expected)

    def test_staging_rejects_private_files_and_unknown_record_fields(self):
        private = self.data / "sent_flashes.txt"
        private.write_text("synthetic private state", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "outside the public data manifest"):
            publication.validate_data(self.data)
        self.assertNotIn("sent_flashes.txt", publication.data_files(self.data, strict=False))
        private.unlink()
        self.change_json("threats.json", lambda records: records[0].update(internal_state="fixture"))
        with self.assertRaisesRegex(ValueError, "unknown field"):
            publication.validate_data(self.data)

    def test_publication_rejects_missing_stable_ids_and_inconsistent_feed_health(self):
        def remove_identity(records):
            for field in ("first_seen_at", "source_ids", "carried_forward"):
                records[0].pop(field)

        self.change_json("threats.json", remove_identity)
        with self.assertRaisesRegex(ValueError, "stable record identity|observation or source IDs"):
            publication.validate_data(self.data)
        collector.write_json(self.data / "threats.json", self.records)

        stamp = "2026-11-25T07:15:00+00:00"
        self.change_json("intelligence_status.json", lambda status: status["collection"].update(
            state="current", data_updated_at=stamp, checked_at=stamp, last_success_at=stamp, feeds=[{
                "id": "fixture", "name": "Fixture", "kind": "collection", "state": "failed",
                "last_success_at": None, "checked_at": stamp, "items": 0,
            }]
        ))
        with self.assertRaisesRegex(ValueError, "health does not match collection"):
            publication.validate_data(self.data)

    def test_candidate_rejects_bad_source_url_and_mismatched_exports(self):
        self.change_json("threats.json", lambda records: records[0].update(url="file:///unavailable"))
        with self.assertRaisesRegex(ValueError, "invalid public URL"):
            publication.validate_data(self.data)
        collector.write_json(self.data / "threats.json", self.records)
        self.change_json("threats.stix.json", lambda bundle: bundle["objects"].pop())
        with self.assertRaisesRegex(ValueError, "do not match"):
            publication.validate_data(self.data)

    def test_candidate_rejects_legacy_indicator_and_rss_dtd(self):
        self.change_json("threats.stix.json", lambda bundle: bundle["objects"][0].update(type="indicator"))
        with self.assertRaisesRegex(ValueError, "Unsupported or duplicate STIX object"):
            publication.validate_data(self.data)
        path = self.data / "threats.stix.json"
        self.write_records(self.records)
        rss = self.data / "feed.xml"
        contents = rss.read_text(encoding="utf-8")
        rss.write_text(contents.replace("<rss ", "<!DOCTYPE rss><rss ", 1), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "DTDs are prohibited"):
            publication.validate_data(self.data)

    def test_restore_clears_obsolete_optional_files(self):
        restored = self.folder / "restored"
        restored.mkdir()
        (restored / "flash_alert.json").write_text("old fixture", encoding="utf-8")
        publication.restore_data(self.data, restored)
        self.assertFalse((restored / "flash_alert.json").exists())
        self.assertEqual((restored / "threats.json").read_bytes(), (self.data / "threats.json").read_bytes())

    def test_restoration_discards_legacy_unvalidated_briefings(self):
        stamp = "2026-11-25T07:15:00+00:00"
        self.change_json("intelligence_status.json", lambda status: status.update(
            daily={"state": "available", "checked_at": stamp, "generated_at": stamp}
        ))
        (self.data / "daily_summary.md").write_text("Legacy fixture without evidence.", encoding="utf-8")
        with self.assertRaises(ValueError):
            publication.validate_data(self.data)
        restored = self.folder / "restored"
        publication.restore_data(self.data, restored)
        self.assertFalse((restored / "daily_summary.md").exists())
        status = json.loads((restored / "intelligence_status.json").read_text(encoding="utf-8"))
        self.assertEqual(status["daily"]["state"], "unavailable")
        self.assertIsNone(status["daily"]["validated_at"])

    def test_publication_revalidates_source_evidence_and_summary_pair(self):
        stamp = "2026-11-25T07:15:00+00:00"
        records = json.loads((self.data / "threats.json").read_text(encoding="utf-8"))
        document = {
            "schema_version": 1, "period": "daily", "coverage": "current",
            "generated_at": stamp, "validated_at": stamp, "sources": snapshot_sources(records, "daily"),
            "selection": {"facts": ["S01"], "assessments": [], "recommendations": []},
        }
        self.change_json("intelligence_status.json", lambda status: status.update(
            daily={"state": "available", "checked_at": stamp, "generated_at": stamp, "validated_at": stamp}
        ))
        summary = self.data / "daily_summary.md"
        evidence = self.data / "daily_briefing.json"
        summary.write_text(render_summary(document), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must be published together"):
            publication.validate_data(self.data)
        evidence.write_text(json.dumps(document), encoding="utf-8")
        publication.validate_data(self.data)
        summary.write_text(render_summary(document) + "Unsupported extra claim.", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "differs from validated content"):
            publication.validate_data(self.data)
        summary.write_text(render_summary(document), encoding="utf-8")
        self.change_json("daily_briefing.json", lambda content: content["selection"]["facts"].append("S99"))
        with self.assertRaisesRegex(ValueError, "Invalid briefing source references"):
            publication.validate_data(self.data)

    def test_checked_in_snapshot_starts_empty(self):
        files = publication.validate_release_data(ROOT / "data")
        self.assertEqual(publication.read_json(files["threats.json"]), [])

    def test_unapproved_article_is_rejected_before_candidate_upload_and_restore(self):
        url = "https://news.example.invalid/story"
        record = assign_identity(dict(self.records[0], title="Uncleared publisher text",
                                      source="Test publisher", source_ids=["test-publisher"]),
                                 url, datetime.now(timezone.utc).isoformat())
        classify_record(record, set(), {}, {}, datetime.now(timezone.utc))
        self.write_records([record])
        publication.validate_data(self.data)
        for operation in ("stage-data", "stage-site", "restore-data"):
            with self.subTest(operation=operation):
                args = ["publication", operation, str(self.data), str(self.folder / operation)]
                with patch.object(sys, "argv", args), self.assertRaises(SystemExit) as failure:
                    publication.main()
                self.assertEqual(failure.exception.code, 1)

    def test_unapproved_retained_briefing_evidence_is_rejected(self):
        stamp = "2026-11-25T07:15:00+00:00"
        sources = snapshot_sources([dict(self.records[0], source="Test publisher",
                                        url="https://news.example.invalid/story")], "daily")
        document = {"schema_version": 1, "period": "daily", "coverage": "current",
                    "generated_at": stamp, "validated_at": stamp, "sources": sources,
                    "selection": {"facts": ["S01"], "assessments": [], "recommendations": []}}
        self.change_json("intelligence_status.json", lambda status: status.update(
            daily={"state": "available", "checked_at": stamp, "generated_at": stamp, "validated_at": stamp}
        ))
        collector.write_json(self.data / "daily_briefing.json", document)
        (self.data / "daily_summary.md").write_text(render_summary(document), encoding="utf-8")
        publication.validate_data(self.data)
        with self.assertRaisesRegex(ValueError, "Briefing includes a source outside the release policy"):
            publication.stage_site(self.data, self.folder / "site", ROOT)

    def test_dependency_locks_contain_direct_pins(self):
        for name in ("requirements", "requirements-audit"):
            inputs = (ROOT / f"{name}.txt").read_text(encoding="utf-8").splitlines()
            locked = (ROOT / f"{name}.lock.txt").read_text(encoding="utf-8").splitlines()
            for requirement in inputs:
                with self.subTest(requirement=requirement):
                    self.assertIn(requirement + " \\", locked)


if __name__ == "__main__":
    unittest.main()
