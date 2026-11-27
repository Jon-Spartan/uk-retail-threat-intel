import copy
import json
from pathlib import Path
import unittest

from retail_intelligence import REGISTER, validate_register


class RetailRegisterTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.register = json.loads((root / REGISTER).read_text(encoding="utf-8"))

    def test_reviewed_register_accepts_timeline_revisions_and_unknown_fields(self):
        validate_register(self.register)
        cleverbridge = self.register["records"][2]
        self.assertEqual(len(cleverbridge["timeline"]), 2)
        self.assertIsNone(cleverbridge["initial_access"])

    def test_rejects_duplicate_id_and_cross_event_source_reuse(self):
        event = copy.deepcopy(self.register["records"][1])
        self.register["records"].append(event)
        with self.assertRaisesRegex(ValueError, "duplicate ID"):
            validate_register(self.register)
        event["id"] = "retail-0099"
        with self.assertRaisesRegex(ValueError, "another record"):
            validate_register(self.register)

    def test_rejects_unsafe_urls_and_unapproved_fields(self):
        report = self.register["records"][1]["timeline"][0]
        report["url"] = "javascript:alert(1)"
        with self.assertRaisesRegex(ValueError, "unsafe evidence URL"):
            validate_register(self.register)
        report["url"] = "https://www.theregister.com.example.org/fake"
        with self.assertRaisesRegex(ValueError, "unapproved evidence URL"):
            validate_register(self.register)
        self.register["records"][0]["private_notes"] = "synthetic fixture"
        with self.assertRaisesRegex(ValueError, "unexpected record fields"):
            validate_register(self.register)

    def test_attributed_press_cannot_claim_first_party_confidence(self):
        self.register["records"][1]["confidence"] = "first_party"
        with self.assertRaisesRegex(ValueError, "first-party evidence"):
            validate_register(self.register)
