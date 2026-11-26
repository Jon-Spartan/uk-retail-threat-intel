import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import requests

from briefings import KEV_PUBLISHER, kev_article_url
from google_chat_alerts import deliver_alert, google_chat_webhook, kev_alerts, reviewed_alerts


NOW = datetime(2026, 11, 26, 12, tzinfo=timezone.utc)
CVE = "CVE-2026-12345"
WEBHOOK = "https://chat.googleapis.com/v1/spaces/test-space/messages?key=fixture&token=fixture"


class GoogleChatAlertsTests(unittest.TestCase):
    def test_only_current_recent_catalogue_additions_are_sent(self):
        item = {
            "reported_cves": [CVE], "source": KEV_PUBLISHER, "url": kev_article_url(CVE),
            "first_seen_at": NOW.isoformat(), "_timestamp": (NOW - timedelta(hours=12)).timestamp(),
            "severity": "CRITICAL", "classification": {"score": 45},
            "affected_products": [{"vendor": "Vendor <users/all>", "product": "Example", "source": "cisa_kev"}],
        }
        collection = {"state": "current", "checked_at": NOW.isoformat()}
        alerts = kev_alerts([item], collection, NOW)
        self.assertIn("RED ALERT", alerts[CVE])
        self.assertIn("Exploitation: confirmed", alerts[CVE])
        self.assertNotIn("<users/all>", alerts[CVE])
        follow_up = kev_alerts([{**item, "severity": "HIGH", "is_new": False}], collection, NOW + timedelta(minutes=15))
        self.assertIn("New CISA KEV", follow_up[CVE])
        for change in (
            {"carried_forward": True}, {"url": "https://example.com/cve"}, {"_timestamp": 0},
            {"first_seen_at": (NOW - timedelta(days=1)).isoformat()}, {"reported_cves": ["unverified"]},
        ):
            self.assertEqual(kev_alerts([{**item, **change}], collection, NOW), {})
        self.assertEqual(kev_alerts([item], {**collection, "state": "failed"}, NOW), {})

    def test_reviewed_alerts_require_primary_source_and_critical_score(self):
        advisory = {
            "cve": CVE, "product": "Example PHP", "reviewed_at": NOW.isoformat(),
            "advisory_url": "https://www.php.net/ChangeLog-8.php", "cvss": 9.2, "exploitation": "unconfirmed",
        }
        alerts = reviewed_alerts([advisory], NOW)
        self.assertIn("Critical (CVSS 9.2)", alerts[CVE])
        self.assertIn("Exploitation: unconfirmed", alerts[CVE])
        self.assertEqual(reviewed_alerts([advisory], NOW + timedelta(hours=3)), {})
        with self.assertRaises(ValueError):
            reviewed_alerts([{**advisory, "advisory_url": "https://php.net.example.com/ChangeLog-8.php"}], NOW)
        with self.assertRaises(ValueError):
            reviewed_alerts([{**advisory, "cvss": 8.9}], NOW)

    def test_only_expected_google_chat_webhooks_are_accepted(self):
        self.assertTrue(google_chat_webhook(WEBHOOK))
        for value in (None, WEBHOOK.replace("https:", "http:"), WEBHOOK + "&messageId=unexpected",
                      WEBHOOK + "&key=duplicate", WEBHOOK.replace("chat.googleapis.com", "chat.googleapis.com.test"),
                      WEBHOOK.replace("chat.googleapis.com", "name@chat.googleapis.com")):
            self.assertFalse(google_chat_webhook(value))

    def test_retries_keep_the_same_id_and_require_a_google_response(self):
        session = Mock()
        session.post.return_value.status_code = 200
        session.post.return_value.json.return_value = {"name": "spaces/test-space/messages/test-message"}
        self.assertTrue(deliver_alert(session, WEBHOOK, "kev", CVE, "First text"))
        session.post.return_value.status_code = 409
        session.post.return_value.json.return_value = {"error": {"status": "ALREADY_EXISTS"}}
        self.assertTrue(deliver_alert(session, WEBHOOK, "kev", CVE, "Updated text"))
        first, retry = session.post.call_args_list
        self.assertEqual(first.kwargs["params"], retry.kwargs["params"])
        self.assertEqual(first.kwargs["params"]["messageId"], "client-uk-retail-kev-cve-2026-12345")
        self.assertFalse(retry.kwargs["allow_redirects"])
        session.post.return_value.json.return_value = {"error": {"status": "UNEXPECTED_CONFLICT"}}
        self.assertFalse(deliver_alert(session, WEBHOOK, "kev", CVE, "Updated text"))
        session.post.side_effect = requests.ReadTimeout("example of a sensitive exception")
        with self.assertLogs(level="WARNING") as events:
            self.assertFalse(deliver_alert(session, WEBHOOK, "kev", CVE, "Updated text"))
        self.assertNotIn("sensitive exception", " ".join(events.output))
