import unittest
from datetime import datetime, timezone

from disclosure_watch import candidates
from official_updates import SOURCES, parse_stories
from test_official_updates import DATE, rss


class DisclosureWatchTests(unittest.TestCase):
    def test_selects_incident_notices_and_excludes_exercises_and_nhs_product_alerts(self):
        checked = datetime(2026, 11, 26, tzinfo=timezone.utc)
        root = "https://www.gov.uk/government/news/"
        rows = parse_stories("moj_cyber", rss(
            ("Cyber security incident update", root + "update", DATE),
            ("Ransomware incident simulation", root + "exercise", DATE),
        ), checked)
        rows.extend(parse_stories("nhs_cyber", rss(
            ("Cyber incident advisory", "https://digital.nhs.uk/cyber-alerts/2026/cc-10000", DATE),
        ), checked))
        rows.sort(key=lambda row: (row["published_at"], row["id"]), reverse=True)
        snapshot = {"checked_at": checked.isoformat(), "sources": dict.fromkeys(SOURCES, "current"), "stories": rows}
        result = candidates(snapshot)
        self.assertEqual([row["url"] for row in result], [root + "update"])
        self.assertEqual(set(result[0]), {"id", "source", "date", "url"})
        snapshot["stories"][0]["url"] = "https://example.invalid/disclosure"
        with self.assertRaises(ValueError):
            candidates(snapshot)
