import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from intelligence_history import FILENAME, aggregate, save_history, validate_history


def status(stamp, state="current"):
    return {"state": state, "last_success_at": stamp, "data_updated_at": stamp}


class IntelligenceHistoryTests(unittest.TestCase):
    def test_replaces_same_day_and_retains_real_gaps(self):
        first = "2026-11-23T12:00:00+00:00"
        latest = "2026-11-26T14:00:00+00:00"
        kev = {"severity": "HIGH", "classification": {"vulnerabilities": [{"id": "CVE-2026-10001", "kev": True}]}}
        self.assertEqual(aggregate([kev, kev], latest)["kev"], 1)
        with TemporaryDirectory() as folder:
            output = Path(folder) / FILENAME
            save_history(output, status(first), [kev])
            save_history(output, status("2026-11-26T12:00:00+00:00"), [kev])
            save_history(output, status(latest), [])
            before = output.read_text(encoding="utf-8")
            data = json.loads(before)
            self.assertEqual([row["collected_at"] for row in data["days"]], [first, latest])
            self.assertEqual(data["days"][-1]["severity"]["HIGH"], 0)
            save_history(output, status(latest, "partial"), [kev])
            self.assertEqual(output.read_text(encoding="utf-8"), before)
            validate_history(data, status(latest, "failed"))
            with self.assertRaisesRegex(ValueError, "does not match"):
                validate_history(data, status(latest), [kev])

    def test_invalid_or_duplicate_days_fail_validation(self):
        stamp = "2026-11-26T12:00:00+00:00"
        row = aggregate([], stamp)
        with self.assertRaisesRegex(ValueError, "counts or date"):
            validate_history({"version": 1, "days": [row, row]}, status(stamp), [])
        row["severity"]["LOW"] = True
        with self.assertRaisesRegex(ValueError, "counts or date"):
            validate_history({"version": 1, "days": [row]}, status(stamp), [])
