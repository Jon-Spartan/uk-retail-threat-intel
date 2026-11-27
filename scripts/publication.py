"""Validate and package the static site from an explicit public-file manifest."""

import argparse
import html
import json
import math
import re
import shutil
from collections import Counter
from datetime import date, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID
from xml.etree import ElementTree

from operations import EXECUTIVE_PREVIOUS_FILE, canonical_article_url, feed_id, record_id
from public_urls import validated_http_url
from briefings import (
    KEV_PUBLISHER, LEGACY_STATUS_FIELDS, STATUS_FIELDS, discard_legacy_briefings, kev_article_url,
    load_briefing_pair, production_cve, utc_time,
)
from classification import ARCHIVE_FIELDS, ATTACK_ID, classification_is_valid, product_entry
from official_updates import FILENAME as OFFICIAL_UPDATES_FILE, validate_updates
from press_updates import FILENAME as PRESS_UPDATES_FILE, validate_press


REQUIRED = ("threats.json", "intelligence_status.json", "threats.stix.json", "feed.xml")
OPTIONAL = (
    EXECUTIVE_PREVIOUS_FILE,
    OFFICIAL_UPDATES_FILE,
    PRESS_UPDATES_FILE,
    "flash_alert.json",
    "daily_summary.md", "daily_summary_date.txt", "daily_briefing.json",
    "weekly_summary.md", "weekly_briefing.json",
)
ASSETS = (
    "index.html",
    "SCORING.md",
    "SOURCES.md",
    "assets/dashboard.js",
    "assets/executive.js",
    "assets/theme.js",
    "assets/dashboard.css",
    "assets/inter.woff2",
    "assets/inter-OFL.txt",
    "assets/jetbrains-mono.woff2",
    "assets/jetbrains-mono-OFL.txt",
    "assets/tailwindcss-LICENSE.txt",
)
RECORD_TEXT = {
    "id", "title", "source", "url", "date", "severity", "subsector", "actor",
    "mitre", "mitre_id", "mitre_tactic", "mitre_name", "summary", "advisory",
}
RECORD_FLAGS = {"is_new", "is_flash", "is_peak_trading"}
MAX_FILE_SIZE = 4 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_file(path):
    require(not path.is_symlink() and path.is_file(), f"Expected a regular file: {path.name}")
    require(path.stat().st_size <= MAX_FILE_SIZE, f"File is too large: {path.name}")
    return path


def data_files(directory, strict):
    require(directory.is_dir() and not directory.is_symlink(), "Expected a regular data directory.")
    if strict:
        require(all(path.name in REQUIRED + OPTIONAL for path in directory.iterdir()),
                "The candidate includes files outside the public data manifest.")
    found = {name: check_file(directory / name) for name in REQUIRED}
    for name in OPTIONAL:
        path = directory / name
        if path.exists() or path.is_symlink():
            found[name] = check_file(path)
    return found


def copy_files(files, destination):
    require(not destination.is_symlink(), "The staging destination must be a regular directory.")
    destination.mkdir(parents=True, exist_ok=True)
    for name, source in files.items():
        target = destination / name
        require(not target.is_symlink(), "A staging file must not be a symlink.")
        shutil.copyfile(source, target)


def unique_object(pairs):
    value = dict(pairs)
    require(len(value) == len(pairs), "Duplicate JSON property.")
    return value


def read_json(path):
    def invalid_constant(_):
        raise ValueError("JSON includes a non-finite value.")

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object,
                      parse_constant=invalid_constant)


def valid_timestamp(value):
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value).utcoffset() is not None
    except ValueError:
        return False


def validate_records(records, allow_legacy=False, require_identity=False):
    require(isinstance(records, list) and len(records) <= 1000, "Invalid collection record list.")
    identified_urls = set()
    identity_fields = {"first_seen_at", "source_ids", "carried_forward"}
    for record in records:
        require(isinstance(record, dict), "Expected a collection record object.")
        legacy = allow_legacy and "classification" not in record
        fields = (RECORD_TEXT - ARCHIVE_FIELDS) | RECORD_FLAGS | {
            "cves", "reported_cves", "tags", "attack_refs", "_timestamp", "classification", "affected_products",
        }
        if legacy:
            fields |= ARCHIVE_FIELDS
        require(set(record) <= fields | identity_fields,
                "A collection record includes an unknown field.")
        require(all(isinstance(record.get(key), str) and record[key].strip()
                    for key in ("id", "title", "source")), "A record lacks its source identity.")
        require(validated_http_url(record.get("url")), "A record has an invalid public URL.")
        if require_identity or identity_fields.intersection(record):
            url = canonical_article_url(record["url"])
            source_ids = record.get("source_ids")
            require(url and record["url"] == url and record["id"] == record_id(url)
                    and url not in identified_urls, "Invalid or duplicate stable record identity.")
            identified_urls.add(url)
            require(utc_time(record.get("first_seen_at")) and isinstance(source_ids, list)
                    and 0 < len(source_ids) <= 32
                    and all(isinstance(value, str) and re.fullmatch(r"[a-z0-9-]{1,100}", value)
                            for value in source_ids)
                    and len(set(source_ids)) == len(source_ids) and feed_id(record["source"]) in source_ids,
                    "Invalid record observation or source IDs.")
            require(type(record.get("carried_forward")) is bool
                    and (not record["carried_forward"] or not (record.get("is_new") or record.get("is_flash"))),
                    "Invalid retained record flags.")
        require(all(record.get(key) is None or isinstance(record[key], str) for key in RECORD_TEXT),
                "A record includes invalid text.")
        require(all(key not in record or isinstance(record[key], bool) for key in RECORD_FLAGS),
                "A record includes invalid flags.")
        confidence = record.get("confidence")
        require(confidence is None or type(confidence) is int and 0 <= confidence <= 100, "Invalid confidence.")
        for key in ("cves", "tags"):
            values = record.get(key, [])
            require(isinstance(values, list) and all(isinstance(value, str) for value in values),
                    f"Invalid record field: {key}")
        require(all(re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", value, re.IGNORECASE)
                    for value in record.get("cves", [])), "Invalid CVE identifier format.")
        products = record.get("affected_products", [])
        require(isinstance(products, list) and len(products) <= 12 and all(
            isinstance(item, dict) and item.get("source") in ("cisa_kev", "cve_list")
            and (item["source"] != "cisa_kev" or record["source"] == KEV_PUBLISHER)
            and item == product_entry(item.get("vendor"), item.get("product"), item["source"])
            for item in products
        ), "Invalid affected product evidence.")
        timestamp = record.get("_timestamp", 0)
        require(type(timestamp) in (int, float) and math.isfinite(timestamp), "Invalid record timestamp.")
        epss = record.get("epss")
        if epss is not None:
            require(isinstance(epss, dict) and set(epss) == {"cve", "score", "raw_score", "percentile"},
                    "Invalid EPSS fields.")
            require(all(isinstance(epss[key], str) for key in ("cve", "score", "percentile"))
                    and type(epss["raw_score"]) in (int, float) and 0 <= epss["raw_score"] <= 1,
                    "Invalid EPSS values.")
        if not legacy:
            mentions = record.get("reported_cves")
            refs = record.get("attack_refs")
            require(isinstance(mentions, list) and all(production_cve(cve) and len(cve) <= 24
                    for cve in mentions) and len(set(mentions)) == len(mentions), "Invalid reported CVE IDs.")
            require(isinstance(refs, list) and len(refs) <= 12 and all(
                isinstance(ref, str) and ATTACK_ID.fullmatch(ref) for ref in refs)
                and len(set(refs)) == len(refs), "Invalid cited technique IDs.")
            require(not any(tag.lower().startswith("actor:") for tag in record.get("tags", [])),
                    "Unsupported actor attribution.")
            if "classification" in record:
                require(classification_is_valid(record), "Classification does not match its evidence.")
            else:
                require(record.get("cves") == [] and record.get("severity") == "UNKNOWN"
                        and not refs and record.get("is_flash") is False, "Invalid unassessed archive record.")


def validate_status(files):
    metadata = read_json(files["intelligence_status.json"])
    require(isinstance(metadata, dict) and set(metadata) <= {"collection", "daily", "weekly"},
            "Invalid intelligence status.")
    collection = metadata.get("collection")
    base_fields = {"state", "checked_at", "data_updated_at"}
    require(isinstance(collection, dict) and set(collection) in (base_fields, base_fields | {"last_success_at", "feeds"}),
            "Invalid collection status fields.")
    state = collection["state"]
    require(state in ("current", "partial", "failed", "snapshot"), "Invalid collection state.")
    checked_at, updated_at = collection["checked_at"], collection["data_updated_at"]
    require((state == "snapshot" and checked_at is None) or valid_timestamp(checked_at),
            "Invalid collection check time.")
    require((state in ("failed", "snapshot") and updated_at is None) or valid_timestamp(updated_at),
            "Invalid dataset timestamp.")
    require(state not in ("failed", "snapshot") or "flash_alert.json" not in files,
            "An unavailable collection cannot publish a flash alert.")
    if "feeds" in collection:
        last_success = collection["last_success_at"]
        checked = utc_time(checked_at)
        require(last_success is None or (checked and utc_time(last_success)
                and utc_time(last_success) <= checked), "Invalid successful collection time.")
        rows = collection["feeds"]
        require(isinstance(rows, list) and len(rows) <= 32, "Invalid source health list.")
        ids, states = set(), set()
        for row in rows:
            require(isinstance(row, dict) and set(row) ==
                    {"id", "name", "kind", "state", "checked_at", "last_success_at", "items"},
                    "Invalid source health fields.")
            identifier, name = row["id"], row["name"]
            require(isinstance(name, str) and 0 < len(name) <= 100 and feed_id(name)
                    and identifier == feed_id(name) and identifier not in ids
                    and row["kind"] == "collection" and row["state"] in ("success", "failed"),
                    "Invalid source health identity.")
            observed, succeeded = utc_time(row["checked_at"]), utc_time(row["last_success_at"])
            require(checked and observed and observed <= checked
                    and (row["last_success_at"] is None or (succeeded and succeeded <= observed))
                    and type(row["items"]) is int and 0 <= row["items"] <= 1000
                    and (row["state"] != "success" or succeeded == observed)
                    and (row["state"] != "failed" or row["items"] == 0),
                    "Invalid source health observation.")
            ids.add(identifier)
            states.add(row["state"])
        expected = {"current": {"success"}, "partial": {"success", "failed"}, "failed": {"failed"}, "snapshot": set()}
        require(states == expected[state] and (state != "current" or last_success == checked_at),
                "Source health does not match collection status.")
    for period in ("daily", "weekly"):
        filename = f"{period}_summary.md"
        evidence = f"{period}_briefing.json"
        has_pair = filename in files and evidence in files
        require((filename in files) == (evidence in files), "Briefing and source evidence must be published together.")
        status = metadata.get(period)
        if status is None:
            require(not has_pair, "Briefing has no generation status.")
            continue
        require(isinstance(status, dict) and set(status) == STATUS_FIELDS,
                "Invalid briefing status fields.")
        require(status["state"] in ("available", "unavailable", "failed"), "Invalid briefing state.")
        require((status["state"] == "unavailable" and status["checked_at"] is None)
                or utc_time(status["checked_at"]), "Invalid briefing check time.")
        require(status["state"] != "available" or has_pair, "An available briefing is missing.")
        if has_pair:
            checked, validated = utc_time(status["checked_at"]), utc_time(status["validated_at"])
            require(checked and validated and checked >= validated, "Invalid briefing validation status.")
            load_briefing_pair(period, files[filename], files[evidence], status)
        else:
            require(status["generated_at"] is None and status["validated_at"] is None,
                    "A briefing timestamp has no validated briefing.")
    if "daily_summary_date.txt" in files:
        content = files["daily_summary_date.txt"].read_text(encoding="utf-8").strip()
        require(date.fromisoformat(content).isoformat() == content, "Invalid daily update date.")
    return metadata


def valid_stix_id(value, kind, version):
    prefix = kind + "--"
    if not isinstance(value, str) or not value.startswith(prefix):
        return False
    suffix = value[len(prefix):]
    try:
        identifier = UUID(suffix)
        return identifier.version == version and str(identifier) == suffix
    except ValueError:
        return False


def validate_stix(path, records):
    bundle = read_json(path)
    require(isinstance(bundle, dict) and set(bundle) == {"type", "id", "objects"}
            and bundle["type"] == "bundle" and valid_stix_id(bundle["id"], "bundle", 4)
            and isinstance(bundle["objects"], list), "Invalid STIX bundle.")
    urls, reports, ids = {}, [], set()
    for obj in bundle["objects"]:
        require(isinstance(obj, dict) and obj.get("spec_version") == "2.1", "Invalid STIX object version.")
        kind, obj_id = obj.get("type"), obj.get("id")
        require(kind in ("url", "report") and (valid_stix_id(obj_id, kind, 5) or (kind == "report" and valid_stix_id(obj_id, kind, 4)))
                and obj_id not in ids, "Unsupported or duplicate STIX object.")
        ids.add(obj_id)
        if kind == "url":
            require(set(obj) == {"type", "id", "spec_version", "value"} and validated_http_url(obj["value"]),
                    "Invalid STIX URL observable.")
            urls[obj_id] = obj["value"]
        else:
            require(set(obj) <= {"type", "id", "spec_version", "name", "description", "created", "modified",
                                 "published", "object_refs", "external_references"}, "Unsupported STIX report fields.")
            require(all(valid_timestamp(obj.get(key)) for key in ("created", "modified", "published")),
                    "Invalid STIX report timestamps.")
            reports.append(obj)
    actual = Counter()
    referenced = set()
    for report in reports:
        refs, external = report.get("object_refs"), report.get("external_references")
        require(isinstance(refs, list) and len(refs) == 1 and isinstance(refs[0], str) and refs[0] in urls,
                "Unresolved STIX source URL.")
        require(isinstance(external, list) and len(external) == 1 and isinstance(external[0], dict)
                and set(external[0]) == {"source_name", "url"}
                and external[0]["url"] == urls[refs[0]]
                and isinstance(external[0]["source_name"], str) and isinstance(report.get("name"), str)
                and isinstance(report.get("description", ""), str),
                "Invalid STIX source reference.")
        actual[urls[refs[0]], external[0]["source_name"], report["name"], report.get("description", "")] += 1
        referenced.add(refs[0])
    expected = Counter((record["url"], record["source"], record["title"], record.get("summary") or "")
                       for record in records)
    require(actual == expected and referenced == set(urls) and len(urls) == len(set(urls.values())),
            "STIX source reports do not match the dashboard dataset.")


def validate_rss(path, records):
    payload = path.read_text(encoding="utf-8")
    require(not re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", payload, re.IGNORECASE), "RSS DTDs are prohibited.")
    rss = ElementTree.fromstring(payload)
    channel = rss.find("channel")
    require(rss.tag == "rss" and rss.attrib == {"version": "2.0"} and len(rss) == 1 and channel is not None
            and validated_http_url(channel.findtext("link")), "Invalid RSS channel.")
    require(all(child.tag in ("title", "link", "description", "language", "lastBuildDate", "item")
                and not child.attrib and (child.tag == "item" or len(child) == 0) for child in channel),
            "Unexpected RSS channel content.")
    actual = []
    for item in channel.findall("item"):
        require([child.tag for child in item] == ["title", "link", "description", "guid"]
                and all(not child.attrib and len(child) == 0 for child in item), "Unexpected RSS item content.")
        actual.append(tuple(child.text or "" for child in item))
    expected = [(f'[{record.get("severity")}] {record["title"]}', record["url"],
                 html.escape(record.get("summary") or "", quote=False), record["url"]) for record in records[:20]]
    require(actual == expected, "RSS items do not match the dashboard dataset.")


def validate_executive_previous(document, collection):
    require(isinstance(document, dict) and set(document) == {"previous_at", "current_at", "record_ids"},
            "Invalid executive comparison fields.")
    previous, current = (utc_time(document[key]) for key in ("previous_at", "current_at"))
    ids = document["record_ids"]
    require(previous and current and previous < current and collection["state"] == "current"
            and document["current_at"] == collection["data_updated_at"]
            and isinstance(ids, list) and len(ids) <= 1000
            and all(isinstance(item, str) and re.fullmatch(r"(?:cisa-kev-cve_[0-9]{4}_[0-9]{4,15}|src-[0-9a-f]{64})", item)
                    for item in ids) and ids == sorted(set(ids)),
            "Invalid executive comparison snapshot.")


def validate_data(directory, allow_legacy=False, *, strict=True):
    files = data_files(directory, strict=strict)
    if OFFICIAL_UPDATES_FILE in files:
        validate_updates(read_json(files[OFFICIAL_UPDATES_FILE]), restoring=allow_legacy)
    if PRESS_UPDATES_FILE in files:
        validate_press(read_json(files[PRESS_UPDATES_FILE]), restoring=allow_legacy)
    records = read_json(files["threats.json"])
    metadata = validate_status(files)
    if EXECUTIVE_PREVIOUS_FILE in files:
        validate_executive_previous(read_json(files[EXECUTIVE_PREVIOUS_FILE]), metadata["collection"])
    validate_records(records, allow_legacy=allow_legacy, require_identity="feeds" in metadata["collection"])
    if "flash_alert.json" in files:
        flash = read_json(files["flash_alert.json"])
        require(isinstance(flash, dict) and flash.get("is_flash") is True and flash in records,
                "Flash alert does not match a current dataset item.")
    validate_stix(files["threats.stix.json"], records)
    validate_rss(files["feed.xml"], records)
    return files


def validate_release_data(directory, allow_legacy=False, *, strict=True):
    """Enforce the approved release sources across data and saved briefings."""
    files = validate_data(directory, allow_legacy=allow_legacy, strict=strict)
    for record in read_json(files["threats.json"]):
        cves = record.get("reported_cves", [])
        require(record["source"] == KEV_PUBLISHER and isinstance(cves, list) and len(cves) == 1 and production_cve(cves[0])
                and record["url"] == kev_article_url(cves[0])
                and record.get("source_ids", [feed_id(KEV_PUBLISHER)]) == [feed_id(KEV_PUBLISHER)],
                "Dataset includes a source outside the release policy.")
    for period in ("daily", "weekly"):
        evidence = files.get(f"{period}_briefing.json")
        if evidence:
            require(all(source["publisher"] == KEV_PUBLISHER for source in read_json(evidence)["sources"]),
                    "Briefing includes a source outside the release policy.")
    return files


def replace_data(files, destination):
    copy_files(files, destination)
    for name in OPTIONAL:
        if name not in files:
            (destination / name).unlink(missing_ok=True)


def restore_data(source, destination):
    files = data_files(source, strict=True)
    status = read_json(files["intelligence_status.json"])
    legacy = isinstance(status, dict) and any(
        isinstance(status.get(period), dict) and set(status[period]) == LEGACY_STATUS_FIELDS
        for period in ("daily", "weekly")
    )
    if not legacy:
        replace_data(validate_release_data(source, allow_legacy=True), destination)
        return
    with TemporaryDirectory() as temporary:
        upgraded = Path(temporary)
        copy_files(files, upgraded)
        discard_legacy_briefings(status, upgraded)
        (upgraded / "intelligence_status.json").write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
        replace_data(validate_release_data(upgraded, allow_legacy=True), destination)


def stage_site(source, destination, root):
    files = validate_release_data(source)
    require(not destination.exists() and not destination.is_symlink(), "Use a fresh site staging directory.")
    assets = {name: check_file(root / name) for name in ASSETS}
    (destination / "assets").mkdir(parents=True)
    copy_files(assets, destination)
    copy_files(files, destination / "data")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("stage-data", "restore-data", "stage-site"))
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        if args.operation == "stage-data":
            require(not args.destination.exists() and not args.destination.is_symlink(),
                    "Use a fresh candidate staging directory.")
            copy_files(validate_release_data(args.source, strict=False), args.destination)
        elif args.operation == "restore-data":
            restore_data(args.source, args.destination)
        else:
            stage_site(args.source, args.destination, Path.cwd())
    except (ValueError, OSError, OverflowError, ElementTree.ParseError) as error:
        parser.exit(1, f"Publication validation failed: {error}\n")


if __name__ == "__main__":
    main()
