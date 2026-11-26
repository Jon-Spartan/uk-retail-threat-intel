import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from feed_transport import FeedError
from press_updates import choose_headings, load_editorial, refresh_press, validate_press


CHECKED = datetime(2026, 11, 26, tzinfo=timezone.utc)
FEED = b"""<rss version="2.0"><channel><title>Fixture</title>
<item><title>A syslog improvement</title><link>https://isc.sans.edu/diary/rss/1234</link>
<pubDate>Wed, 25 Nov 2026 00:00:00 GMT</pubDate></item>
<item><title>A detection at 192.0.2.9</title><link>https://isc.sans.edu/diary/rss/1235</link>
<pubDate>Wed, 25 Nov 2026 00:00:00 GMT</pubDate></item>
<item><title>A critical patch</title><link>https://example.com/diary/rss/1236</link>
<pubDate>Wed, 25 Nov 2026 00:00:00 GMT</pubDate></item>
</channel></rss>"""


class PressUpdatesTests(unittest.TestCase):
    def test_curated_press_and_research_have_distinct_provenance(self):
        editorial = load_editorial()
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "press_updates.json"
            with patch("feed_transport.download_source", return_value=FEED), patch(
                "press_updates.choose_headings", return_value=dict.fromkeys(editorial, 1)
            ) as choose:
                refresh_press(path, CHECKED)
                choose.assert_called_once_with({key: record["headings"] for key, record in editorial.items()})
            document = json.loads(path.read_text(encoding="utf-8"))
            validate_press(document)
            research = [item for item in document["stories"] if item["source"] == "sans"]
            self.assertEqual([item["url"] for item in research], ["https://isc.sans.edu/diary/1234"])
            self.assertEqual({item["heading_kind"] for item in document["stories"]}, {"publisher", "ai-assisted"})
            with patch("feed_transport.download_source", side_effect=FeedError("Unavailable")), patch(
                "press_updates.choose_headings", return_value={}
            ) as choose:
                refresh_press(path, CHECKED + timedelta(minutes=15))
                choose.assert_called_once_with({})
            retry = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(retry["stories"], document["stories"])
            self.assertEqual(retry["research"], "unavailable")
            story = next(item for item in retry["stories"] if item["source"] == "bleeping")
            story["title"] = "A claim without reviewed evidence"
            with self.assertRaises(ValueError):
                validate_press(retry)
            validate_press(retry, restoring=True)

    def test_language_model_cannot_supply_free_text_or_unknown_choices(self):
        with patch.dict("os.environ", {"GEMINI_API_KEY": "fixture-only"}), patch("google.genai.Client") as client:
            model = client.return_value.__enter__.return_value.models.generate_content
            model.return_value.function_calls = None
            for payload, expected in [
                ('{"id":1}', {"id": 1}), ('{"id":2}', {}), ('{"id":true}', {}),
                ('{"id":"an unsupported claim"}', {}), ('{"id":0,"extra":1}', {}),
            ]:
                model.return_value.text = payload
                self.assertEqual(choose_headings({"id": ["First", "Second"]}), expected)

    def test_reviewed_fallback_can_be_upgraded_after_key_becomes_available(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "press_updates.json"
            with patch("feed_transport.download_source", return_value=FEED), patch(
                "press_updates.choose_headings", return_value={}
            ) as choose:
                refresh_press(path, CHECKED)
                refresh_press(path, CHECKED + timedelta(minutes=15))
                choose.assert_called_with({})
                choose.return_value = dict.fromkeys(load_editorial(), 1)
                refresh_press(path, CHECKED + timedelta(days=1))
            upgraded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual({item["heading_kind"] for item in upgraded["stories"]}, {"publisher", "ai-assisted"})
