"""Collect public headlines independently of the vulnerability dataset."""

import json
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from html import unescape
from pathlib import Path
from urllib.parse import urlsplit

from briefings import utc_time
from operations import atomic_write, record_id
from public_urls import validated_http_url


FILENAME = "official_updates.json"
RETENTION = timedelta(days=30)
PER_SOURCE_LIMIT = 8
SOURCES = {
    "ncsc": ("www.ncsc.gov.uk", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
             r"/(?:news|blogs|guidance|report)/[a-z0-9-]+"),
    "cisa": ("www.cisa.gov", "https://www.cisa.gov/cybersecurity-advisories/all.xml",
             r"/news-events/(?:alerts/[0-9]{4}/[0-9]{2}/[0-9]{2}|cybersecurity-advisories)/[a-z0-9-]+"),
}
KEV_ANNOUNCEMENT = re.compile(r"known[- ]exploited[- ]vulnerabilit|\bkev\b", re.IGNORECASE)


def story_url(source, value):
    if not validated_http_url(value):
        return None
    host, _, pattern = SOURCES[source]
    parsed = urlsplit(value)
    path = parsed.path.rstrip("/")
    if (parsed.scheme != "https" or parsed.netloc.lower() not in {host, host.removeprefix("www.")}
            or not re.fullmatch(pattern, path) or (source == "cisa" and KEV_ANNOUNCEMENT.search(path))):
        return None
    return f"https://{host}{path}"


def valid_title(title):
    return (isinstance(title, str) and 0 < len(title) <= 240 and title == " ".join(title.split())
            and not any(char in "<>" or unicodedata.category(char).startswith("C") for char in title))


def story_order(story):
    return utc_time(story["published_at"]), story["id"]


def validate_updates(document):
    if not isinstance(document, dict) or set(document) != {"checked_at", "sources", "stories"}:
        raise ValueError("Invalid official updates document.")
    checked = utc_time(document["checked_at"])
    states, stories = document["sources"], document["stories"]
    if (not checked or not isinstance(states, dict) or states.keys() != SOURCES.keys()
            or any(state not in ("current", "unavailable") for state in states.values())
            or not isinstance(stories, list) or len(stories) > len(SOURCES) * PER_SOURCE_LIMIT):
        raise ValueError("Invalid official updates coverage.")
    ids = set()
    counts = dict.fromkeys(SOURCES, 0)
    for story in stories:
        if not isinstance(story, dict) or set(story) != {"id", "source", "title", "url", "published_at"}:
            raise ValueError("Invalid official story fields.")
        source, url = story["source"], story["url"]
        published = utc_time(story["published_at"])
        if (not isinstance(source, str) or source not in SOURCES or not url or story_url(source, url) != url
                or story["id"] != record_id(url) or story["id"] in ids or not valid_title(story["title"])
                or (source == "cisa" and KEV_ANNOUNCEMENT.search(story["title"]))
                or not published or not checked - RETENTION <= published <= checked):
            raise ValueError("Invalid official story.")
        ids.add(story["id"])
        counts[source] += 1
    if max(counts.values()) > PER_SOURCE_LIMIT or stories != sorted(stories, key=story_order, reverse=True):
        raise ValueError("Invalid official story count or order.")


def parse_stories(source, body, checked):
    import feedparser

    parsed = feedparser.parse(body)
    if parsed.bozo or not parsed.version:
        raise ValueError("Unusable official feed.")
    stories = {}
    for raw_entry in parsed.entries:
        entry = dict(raw_entry)
        url = story_url(source, entry.get("link"))
        title = " ".join(unescape(entry.get("title", "")).split())
        date = entry.get("published_parsed") or entry.get("updated_parsed")
        if (not url or not valid_title(title) or not date
                or (source == "cisa" and KEV_ANNOUNCEMENT.search(title))):
            continue
        published = datetime(*date[:6], tzinfo=timezone.utc)
        if checked - RETENTION <= published <= checked:
            story = {"id": record_id(url), "source": source, "title": title, "url": url,
                     "published_at": published.isoformat()}
            if url not in stories or story_order(story) > story_order(stories[url]):
                stories[url] = story
    return sorted(stories.values(), key=story_order, reverse=True)[:PER_SOURCE_LIMIT]


def refresh_updates(path, checked=None):
    from requests import RequestException

    from feed_transport import download_source

    checked = checked or datetime.now(timezone.utc).replace(microsecond=0)
    prior = []
    if path.exists():
        previous = json.loads(path.read_text(encoding="utf-8"))
        validate_updates(previous)
        prior = previous["stories"]

    states, stories = {}, []
    for source, (_, feed, _) in SOURCES.items():
        try:
            stories.extend(parse_stories(source, download_source(feed), checked))
        except (RequestException, ValueError, OverflowError):
            states[source] = "unavailable"
            stories.extend(story for story in prior if story["source"] == source
                           and checked - RETENTION <= utc_time(story["published_at"]) <= checked)
            print(f"Official feed unavailable: {source}.")
        else:
            states[source] = "current"

    document = {"checked_at": checked.isoformat(), "sources": states,
                "stories": sorted(stories, key=story_order, reverse=True)}
    validate_updates(document)
    atomic_write(path, json.dumps(document, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    refresh_updates(Path("data") / FILENAME)
