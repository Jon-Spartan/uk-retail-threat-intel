import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import threat_intel_pipeline as pipeline
from classification import (
    EPSS_URL, classification_is_valid, classify_record, cve_source_url, cvss_severity, extract_attack_refs,
    parse_cve_record, parse_epss, qualifies_for_flash, sanitize_archive,
)
from scripts.publication import validate_records


NOW = datetime(2026, 11, 25, 12, tzinfo=timezone.utc)
A = "CVE-2024-0001"
B = "CVE-2025-12345"
PUBLISHED = {"state": "published", "cvss": {"version": "3.1", "score": 8.0}}


def article(**changes):
    fields = {
        "id": "fixture-1", "title": "UK checkout advisory", "source": "NCSC UK Advisories",
        "url": "https://www.ncsc.gov.uk/fixture", "summary": "Retail payment monitoring",
        "reported_cves": [A], "attack_refs": [], "is_new": True, "_timestamp": NOW.timestamp(),
    }
    return {**fields, **changes}


class ClassificationTests(unittest.TestCase):
    def test_same_technical_severity_can_have_different_retail_priority(self):
        probabilities = {A: {"probability": 0.55, "date": NOW.date().isoformat()}}
        direct = classify_record(article(), {A}, {A: PUBLISHED}, probabilities, NOW)
        general = classify_record(article(title="Enterprise advisory", summary="",
                                         source="Unknown", url="https://source.example.invalid/"),
                                  set(), {A: PUBLISHED}, {}, NOW)
        self.assertEqual(direct["severity"], general["severity"])
        self.assertEqual(direct["severity"], "HIGH")
        model = direct["classification"]
        self.assertEqual(model["components"], {
            "technical": 16, "exploitation": 20, "kev": 10, "epss": 15, "retail": 20,
            "source": 5, "confidence": 5, "freshness": 5,
        })
        self.assertEqual(model["score"], 96)
        self.assertEqual(general["classification"]["score"], 24)
        self.assertTrue(qualifies_for_flash(direct))
        self.assertFalse(qualifies_for_flash(general))
        self.assertTrue(classification_is_valid(direct))

    def test_missing_and_rejected_evidence_does_not_confirm_exploitation(self):
        item = article(title="Actively exploited critical vulnerability claim", summary="",
                       _timestamp=0, severity="CRITICAL")
        classify_record(item, None, {}, {}, NOW)
        self.assertEqual(item["severity"], "UNKNOWN")
        self.assertEqual(item["cves"], [])
        self.assertEqual(item["reported_cves"], [A])
        self.assertFalse(item["classification"]["kev_catalog_available"])
        self.assertEqual(item["classification"]["components"]["freshness"], 0)
        self.assertEqual(item["classification"]["exploitation"], "unknown")
        rejected = classify_record(article(), {A}, {A: {"state": "rejected", "cvss": None}}, {}, NOW)
        self.assertEqual(rejected["cves"], [])
        self.assertEqual(rejected["classification"]["components"]["kev"], 0)
        self.assertFalse(qualifies_for_flash(rejected))

    def test_cvss_from_published_exact_cve_record_prefer_cna_version(self):
        def metric(key, version, score):
            return {key: {"version": version, "baseScore": score, "vectorString": f"CVSS:{version}/fixture"}}

        payload = {"dataType": "CVE_RECORD", "dataVersion": "5.2",
                   "cveMetadata": {"cveId": A, "state": "PUBLISHED"},
                   "containers": {"cna": {"metrics": [metric("cvssV3_1", "3.1", 9.8),
                                                       metric("cvssV4_0", "4.0", 8.0)]},
                                  "adp": [{"metrics": [metric("cvssV4_0", "4.0", 10.0)]}]}}
        self.assertEqual(parse_cve_record(payload, A), {"state": "published", "cvss": {"version": "4.0", "score": 8}})
        self.assertIsNone(parse_cve_record(payload, B))
        payload["cveMetadata"]["state"] = "REJECTED"
        self.assertEqual(parse_cve_record(payload, A), {"state": "rejected", "cvss": None})
        self.assertEqual([cvss_severity(value) for value in (None, 0, 0.1, 4, 7, 9)],
                         ["UNKNOWN", "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"])

    def test_only_declared_cna_products_are_published(self):
        payload = {"dataType": "CVE_RECORD", "dataVersion": "5.2",
                   "cveMetadata": {"cveId": A, "state": "PUBLISHED"},
                   "containers": {"cna": {"affected": [
                       {"vendor": "Example Vendor", "product": "Edge Service",
                        "versions": [{"version": "1", "status": "affected"}]},
                       {"vendor": "Example Vendor", "product": "Independent Product",
                        "versions": [{"version": "1", "status": "unaffected"}]},
                       {"vendor": "n/a", "product": "Placeholder", "defaultStatus": "affected"},
                       {"vendor": "Vendor", "product": "<bad>", "defaultStatus": "affected"},
                   ]}, "adp": [{"affected": [{"vendor": "Other", "product": "Third-party",
                                               "defaultStatus": "affected"}]}]}}
        primary = parse_cve_record(payload, A)
        expected = [{"vendor": "Example Vendor", "product": "Edge Service", "source": "cve_list"}]
        self.assertEqual(primary["affected_products"], expected)
        record = classify_record(article(), set(), {A: primary}, {}, NOW)
        self.assertEqual(record["affected_products"], expected)
        validate_records([record])
        record["affected_products"][0]["source"] = "unverified"
        with self.assertRaisesRegex(ValueError, "Invalid affected product evidence"):
            validate_records([record])

    def test_remediation_retains_explicit_cna_ranges_and_matching_vendor_advisories(self):
        advisory = f"https://msrc.microsoft.com/update-guide/vulnerability/{A}"
        product = {"vendor": "Example Vendor", "product": "Gateway"}
        payload = {"dataType": "CVE_RECORD", "dataVersion": "5.2",
                   "cveMetadata": {"cveId": A, "state": "PUBLISHED"}, "containers": {"cna": {
                       "affected": [{**product, "versions": [
                           {"version": "1.0", "status": "affected", "lessThan": "1.5"},
                           {"version": "2.0", "status": "affected", "lessThanOrEqual": "2.3"},
                           {"version": "3.0", "status": "affected"},
                           {"version": "4.0", "status": "affected", "lessThan": "*"},
                           {"version": "5.0", "status": "affected", "lessThan": "6.0",
                            "changes": [{"at": "5.5", "status": "unaffected"}]},
                           {"version": "7.0", "status": "unaffected"},
                       ]}],
                       "references": [
                           {"url": advisory, "tags": ["vendor-advisory"]},
                           {"url": advisory.replace(A, B), "tags": ["vendor-advisory"]},
                           {"url": advisory.replace(".com/", ".com.example.invalid/"), "tags": ["vendor-advisory"]},
                           {"url": advisory + "?bad=1", "tags": ["vendor-advisory"]},
                           {"url": f"https://access.redhat.com/security/cve/{A}", "tags": ["technical-description"]},
                       ],
                   }}}
        primary = parse_cve_record(payload, A)
        expected = {"affected_versions": [{**product, "from": "1.0", "before": "1.5"},
                                          {**product, "from": "2.0", "through": "2.3"},
                                          {**product, "from": "3.0"}],
                    "vendor_advisories": [advisory]}
        self.assertEqual(primary["remediation"], expected)
        record = classify_record(article(), {A}, {A: primary}, {}, NOW)
        vulnerability = record["classification"]["vulnerabilities"][0]
        self.assertEqual(vulnerability["remediation"], expected)
        validate_records([record])
        vulnerability["remediation"]["vendor_advisories"] = [advisory.replace(A, B)]
        with self.assertRaisesRegex(ValueError, "Classification does not match its evidence"):
            validate_records([record])

    def test_epss_staleness_per_cve_and_conflicts(self):
        day = NOW.date()
        rows = [
            {"cve": A, "date": day.isoformat(), "epss": "0.20"},
            {"cve": B, "date": (day - timedelta(days=1)).isoformat(), "epss": "0.60"},
            {"cve": B, "date": (day - timedelta(days=9)).isoformat(), "epss": "0.99"},
            {"cve": B, "date": (day + timedelta(days=1)).isoformat(), "epss": "0.95"},
            {"cve": "CVE-2024-9999", "date": day.isoformat(), "epss": "0.95"},
        ]
        epss = parse_epss(rows, {A, B}, day)
        classified = classify_record(article(reported_cves=[A, B]), set(), {A: PUBLISHED, B: PUBLISHED}, epss, NOW)
        self.assertEqual([cve["epss"]["probability"] for cve in classified["classification"]["vulnerabilities"]],
                         [0.20, 0.60])
        self.assertEqual(classified["classification"]["components"]["epss"], 15)
        self.assertNotIn(A, parse_epss(rows + [{"cve": A, "date": day.isoformat(), "epss": "0.25"}], {A, B}, day))

    def test_attack_references_require_explicit_mitre_links(self):
        summary = (
            "Reporting mentions T1059, ransomware, public infrastructure and an actor. "
            '<a href="https://attack.mitre.org/techniques/T1056/004/">Reported source citation</a>'
            '<a href="https://attack.mitre.org.example.invalid/techniques/T1190/">Untrusted host</a>'
        )
        self.assertEqual(extract_attack_refs(summary), ["T1056.004"])
        self.assertEqual(extract_attack_refs("T1190 and ransomware"), [])

    def test_source_lookups_validate_and_send_verified_ids_to_epss(self):
        published = {"dataType": "CVE_RECORD", "dataVersion": "5.2", "containers": {"cna": {}},
                     "cveMetadata": {"cveId": A, "state": "PUBLISHED"}}
        rejected = {"dataType": "CVE_RECORD", "dataVersion": "5.2",
                    "cveMetadata": {"cveId": B, "state": "REJECTED"}}
        requests = []

        def get(url, **options):
            requests.append((url, options))
            values = {cve_source_url(A): published, cve_source_url(B): rejected,
                      EPSS_URL: {"data": [{"cve": A, "date": NOW.date().isoformat(), "epss": "0.4"}]}}
            return values[url]

        with patch.object(pipeline, "download_json", side_effect=get):
            records, epss = pipeline.load_vulnerability_evidence([article(reported_cves=[A, B])], {B}, NOW)
        self.assertEqual([request[0] for request in requests], [cve_source_url(B), cve_source_url(A), EPSS_URL])
        self.assertEqual(requests[-1][1]["params"]["cve"], A)
        self.assertEqual(records[B]["state"], "rejected")
        self.assertEqual(epss[A]["probability"], 0.4)

    def test_publication_rejects_tampered_priority_and_legacy_inferences(self):
        item = classify_record(article(), set(), {A: PUBLISHED}, {}, NOW)
        validate_records([item])
        item["classification"]["score"] += 10
        with self.assertRaisesRegex(ValueError, "does not match its evidence"):
            validate_records([item])
        archived = article(severity="CRITICAL", actor="Heuristic marker", mitre_id="T1190", cves=[A])
        with self.assertRaisesRegex(ValueError, "unknown field"):
            validate_records([archived])
        self.assertTrue(sanitize_archive([archived]))
        validate_records([archived])
        self.assertNotIn("actor", archived)
        self.assertNotIn("mitre_id", archived)
        self.assertFalse(sanitize_archive([archived]))


if __name__ == "__main__":
    unittest.main()
