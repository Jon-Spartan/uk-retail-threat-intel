"""Public record identity, collection state, and scheduling primitives."""

import errno
import hashlib
import os
import re
from contextlib import contextmanager
from datetime import datetime, time, timedelta
from tempfile import NamedTemporaryFile
from urllib.parse import parse_qs, unquote_plus, urlsplit, urlunsplit
from zoneinfo import ZoneInfo

from briefings import KEV_URL, kev_article_url, production_cve, utc_time
from classification import record_source_tier
from public_urls import validated_http_url


LOOKBACK_DAYS = 7
LONDON = "Europe/London"
TRACKING_PARAMETERS = {"fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid"}


def canonical_article_url(value):
    if not validated_http_url(value):
        return None
    parsed = urlsplit(value)
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    if port and (parsed.scheme, port) not in (("https", 443), ("http", 80)):
        host += f":{port}"
    fields = []
    for field in parsed.query.split("&"):
        name = unquote_plus(field.split("=", 1)[0]).lower()
        if field and name not in TRACKING_PARAMETERS and not name.startswith("utm_"):
            fields.append(field)
    canonical = urlunsplit((parsed.scheme, host, parsed.path or "/", "&".join(fields), ""))
    return canonical if validated_http_url(canonical) else None


def record_id(canonical):
    if canonical.startswith(KEV_URL + "?"):
        identifiers = parse_qs(urlsplit(canonical).query).get("search_api_fulltext", [])
        if len(identifiers) == 1 and production_cve(identifiers[0]) and canonical == kev_article_url(identifiers[0]):
            return "cisa-kev-" + identifiers[0].lower().replace("-", "_")
    return "src-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def feed_id(name):
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def assign_identity(record, canonical, first_seen_at):
    record.update(id=record_id(canonical), url=canonical, first_seen_at=first_seen_at)
    record.setdefault("source_ids", [feed_id(record["source"])])
    record.setdefault("carried_forward", False)
    return record


def deduplicate(records):
    results = {}
    tiers = {"authority": 2, "reporting": 1, "unassessed": 0}
    for record in records:
        url = record["url"]
        previous = results.get(url)
        if previous is None:
            results[url] = record
            continue
        def rank(item):
            return (tiers[record_source_tier(item)], item.get("_timestamp", 0),
                    item["source"], item["title"], item.get("summary", ""))
        preferred = max((previous, record), key=rank)
        preferred["source_ids"] = sorted(set(previous["source_ids"]) | set(record["source_ids"]))
        preferred["first_seen_at"] = min(previous["first_seen_at"], record["first_seen_at"])
        results[url] = preferred
    return list(results.values())


def merge_outage_records(records, previous, failed_sources, now):
    seen = {record["url"] for record in records}
    cutoff = (now - timedelta(days=LOOKBACK_DAYS)).timestamp()
    for record in previous:
        if record["url"] in seen or not failed_sources.intersection(record["source_ids"]):
            continue
        first_seen = utc_time(record["first_seen_at"])
        recorded_at = record.get("_timestamp") or first_seen.timestamp()
        if cutoff <= recorded_at <= now.timestamp():
            records.append({**record, "is_new": False, "is_flash": False, "carried_forward": True})
            seen.add(record["url"])
    return records


def record_health(name, state, items, now, previous, kind="collection"):
    identifier = feed_id(name)
    stamp = now.isoformat()
    return {
        "id": identifier, "name": name, "kind": kind, "state": state, "checked_at": stamp,
        "last_success_at": stamp if state == "success" else previous.get(identifier, {}).get("last_success_at"),
        "items": items,
    }


def brief_slot(period, when):
    local = when.astimezone(ZoneInfo(LONDON))
    day = local.date()
    if period == "daily":
        if local.weekday() >= 5 or local.time() < time(7, 15):
            return None
        return day.isoformat()
    since_friday = (local.weekday() - 4) % 7
    if since_friday > 2 or (since_friday == 0 and local.time() < time(16)):
        return None
    return (day - timedelta(days=since_friday)).isoformat()


def notification_slot(period, when):
    local_day = when.astimezone(ZoneInfo(LONDON)).date()
    if period == "weekly":
        # Manual weekly editions belong to the most recent Friday's slot.
        local_day -= timedelta(days=(local_day.weekday() - 4) % 7)
    return local_day.isoformat()


def daily_slot_end(when):
    london = ZoneInfo(LONDON)
    tomorrow = when.astimezone(london).date() + timedelta(days=1)
    return datetime.combine(tomorrow, time.min, london)


def due_briefing(period, status, now):
    slot = brief_slot(period, now)
    if slot is None:
        return False
    checked = utc_time(status.get(period, {}).get("checked_at"))
    return not checked or notification_slot(period, checked) != slot


@contextmanager
def collection_lock(path):
    """Hold an operating-system lock for a complete collection and write cycle."""
    with path.open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                raise
            yield False
            return
        yield True


def atomic_write(path, contents):
    if isinstance(contents, str):
        contents = contents.encode("utf-8")
    with NamedTemporaryFile(dir=path.parent, prefix="." + path.name, suffix=".tmp", delete=False) as handle:
        temporary = handle.name
        try:
            handle.write(contents)
        except OSError:
            handle.close()
            os.unlink(temporary)
            raise
    try:
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
