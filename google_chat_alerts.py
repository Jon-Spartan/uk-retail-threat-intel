"""Send flash alerts from validated public evidence to a configured Google Chat space."""

import argparse
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import requests

from briefings import KEV_PUBLISHER, kev_article_url, production_cve, utc_time
from public_urls import validated_http_url
from scripts.publication import read_json, validate_release_data


RETRY_WINDOW = timedelta(hours=2)
MAX_KEV_AGE = timedelta(days=2)
REVIEW_FILE = Path(__file__).resolve().parent / "editorial" / "urgent-vulnerabilities.json"
ADVISORY_PATHS = {
    "www.cisa.gov": r"/news-events/(?:alerts/[0-9]{4}/[0-9]{2}/[0-9]{2}|cybersecurity-advisories)/[a-z0-9-]+",
    "www.ncsc.gov.uk": r"/(?:news|blogs|guidance|report)/[a-z0-9-]+",
    "www.php.net": r"/ChangeLog-8\.php",
}


def google_chat_webhook(value):
    if not validated_http_url(value):
        return False
    url = urlsplit(value)
    fields = parse_qs(url.query, keep_blank_values=True)
    return (url.scheme == "https" and url.netloc == "chat.googleapis.com" and not url.fragment
            and re.fullmatch(r"/v1/spaces/[a-zA-Z0-9_-]+/messages", url.path) is not None
            and fields.keys() == {"key", "token"}
            and all(len(parts) == 1 and re.fullmatch(r"[a-zA-Z0-9_./+=-]{1,256}", parts[0])
                    for parts in fields.values()))


def clean_product(value):
    return " ".join(re.sub(r"[^a-zA-Z0-9 ().+-]", " ", value[:100]).split()) if isinstance(value, str) else ""


def validates_cve(value):
    return production_cve(value) and len(value) <= 24


def kev_alerts(records, collection, now):
    checked = utc_time(collection.get("checked_at"))
    if collection.get("state") not in ("current", "partial") or not checked or not timedelta() <= now - checked <= RETRY_WINDOW:
        return {}
    result = {}
    for record in records:
        cves = record["reported_cves"]
        first_seen = utc_time(record.get("first_seen_at"))
        added = datetime.fromtimestamp(record.get("_timestamp", 0), tz=timezone.utc)
        if (record.get("carried_forward") or not first_seen or not timedelta() <= now - first_seen <= RETRY_WINDOW
                or not timedelta() <= now - added < MAX_KEV_AGE
                or record["source"] != KEV_PUBLISHER or len(cves) != 1 or not validates_cve(cves[0])
                or record["url"] != kev_article_url(cves[0])):
            continue
        cve = cves[0]
        severity = record["severity"]
        score = record.get("classification", {}).get("score", 0)
        red = severity == "CRITICAL" or score >= 50
        heading = "🚨 *RED ALERT · CISA KEV*" if red else "⚠️ *New CISA KEV*"
        product = next((p for p in record.get("affected_products", []) if p.get("source") == "cisa_kev"), {})
        name = " ".join(filter(None, [clean_product(product.get("vendor")), clean_product(product.get("product"))]))
        result[cve] = (f"{heading}\n{cve}" + (f" · {name}" if name else "")
                       + f"\nSeverity: {severity.title()}\nExploitation: confirmed (CISA catalogue)."
                       + f"\nVerify applicability and follow vendor remediation.\n{record['url']}")
    return result


def reviewed_alerts(entries, now):
    if not isinstance(entries, list):
        raise ValueError("Invalid reviewed alert list.")
    result = {}
    identifiers = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "cve", "product", "reviewed_at", "advisory_url", "cvss", "exploitation",
        }:
            raise ValueError("Invalid reviewed alert fields.")
        cve, product, url = entry["cve"], entry["product"], entry["advisory_url"]
        cvss, exploitation = entry["cvss"], entry["exploitation"]
        reviewed = utc_time(entry["reviewed_at"])
        parsed = urlsplit(url) if validated_http_url(url) else None
        pattern = ADVISORY_PATHS.get(parsed.netloc) if parsed else None
        if (not validates_cve(cve) or cve in identifiers or not product or clean_product(product) != product
                or type(cvss) not in (int, float) or not 9 <= cvss <= 10
                or exploitation not in ("confirmed", "unconfirmed")
                or not reviewed or not pattern or parsed.scheme != "https" or parsed.query
                or parsed.fragment or not re.fullmatch(pattern, parsed.path)):
            raise ValueError("Invalid reviewed alert evidence.")
        identifiers.add(cve)
        if timedelta() <= now - reviewed <= RETRY_WINDOW:
            status = "confirmed by cited advisory" if exploitation == "confirmed" else "unconfirmed"
            result[cve] = (f"🚨 *RED ALERT · Reviewed advisory*\n{cve} · {product}"
                           f"\nSeverity: Critical (CVSS {cvss:.1f})\nExploitation: {status}."
                           f"\nVerify applicability and follow vendor remediation.\n{url}")
    return result


def deliver_alert(session, webhook, kind, cve, message):
    message_id = f"client-uk-retail-{kind}-{cve.lower()}"
    try:
        response = session.post(webhook, params={"messageId": message_id},
                                json={"text": message}, allow_redirects=False, timeout=(3, 8))
        if 200 <= response.status_code < 300:
            # Verify that Chat assigned a message resource before accepting a successful send.
            name = response.json().get("name", "")
            return isinstance(name, str) and name.startswith(urlsplit(webhook).path.removeprefix("/v1/") + "/")
        if response.status_code == 409:
            return response.json().get("error", {}).get("status") == "ALREADY_EXISTS"
        logging.warning("Google Chat returned HTTP %d.", response.status_code)
    except (requests.RequestException, ValueError, AttributeError):
        logging.warning("Google Chat delivery could not be verified.")
    return False


def run(directory, webhook, now):
    if not google_chat_webhook(webhook):
        raise ValueError("Provide a Google Chat incoming webhook through the configured secret.")
    files = validate_release_data(directory)
    status = read_json(files["intelligence_status.json"])
    kev = kev_alerts(read_json(files["threats.json"]), status["collection"], now)
    reviewed = reviewed_alerts(read_json(REVIEW_FILE), now)
    alerts = [("kev", cve, message) for cve, message in kev.items()]
    alerts.extend(("urgent", cve, message) for cve, message in reviewed.items() if cve not in kev)
    failed = 0
    with requests.Session() as session:
        session.trust_env = False
        for index, (kind, cve, message) in enumerate(alerts):
            if index:
                time.sleep(1.1)  # Google Chat shares a one-request-per-second quota per space.
            failed += not deliver_alert(session, webhook, kind, cve, message)
    print(f"Eligible flash alerts: {len(alerts)}. Unconfirmed delivery attempts: {failed}.")
    return failed == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        sent = run(args.directory, os.getenv("GOOGLE_CHAT_WEBHOOK_URL"), datetime.now(timezone.utc))
    except (ValueError, OSError, KeyError, OverflowError):
        parser.exit(1, "Google Chat alert settings or release data could not be validated.\n")
    if not sent:
        parser.exit(1, "A Google Chat delivery could not be verified.\n")


if __name__ == "__main__":
    main()
