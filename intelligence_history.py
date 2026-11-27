"""Bounded daily aggregates from complete public vulnerability snapshots."""

import json
from datetime import timedelta

from briefings import utc_time
from operations import atomic_write

FILENAME = "intelligence_history.json"
RETENTION_DAYS = 90
BANDS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def aggregate(records, collected_at):
    severity = dict.fromkeys(BANDS, 0)
    kev_ids = set()
    for record in records:
        band = record.get("severity") if record.get("classification") else "UNKNOWN"
        severity[band if band in severity else "UNKNOWN"] += 1
        kev_ids.update(cve["id"] for cve in (record.get("classification") or {}).get("vulnerabilities", ())
                       if cve.get("kev") is True)
    return {"collected_at": collected_at, "severity": severity, "kev": len(kev_ids)}


def validate_history(document, collection, records=None):
    if (not isinstance(document, dict) or set(document) != {"version", "days"}
            or type(document["version"]) is not int or document["version"] != 1
            or not isinstance(document["days"], list) or len(document["days"]) > RETENTION_DAYS):
        raise ValueError("Invalid intelligence history.")
    previous = None
    latest = utc_time(collection.get("last_success_at"))
    if not latest:
        raise ValueError("Intelligence history requires a successful collection timestamp.")
    earliest = latest.date() - timedelta(days=RETENTION_DAYS - 1)
    for row in document["days"]:
        if not isinstance(row, dict) or set(row) != {"collected_at", "severity", "kev"}:
            raise ValueError("Invalid intelligence history day.")
        stamp = utc_time(row["collected_at"])
        severity = row["severity"]
        if (not stamp or stamp > latest or stamp.date() < earliest
                or (previous and stamp.date() <= previous.date())
                or not isinstance(severity, dict) or set(severity) != set(BANDS)
                or any(type(value) is not int or not 0 <= value <= 1000 for value in severity.values())
                or sum(severity.values()) > 1000 or type(row["kev"]) is not int or not 0 <= row["kev"] <= 1000):
            raise ValueError("Invalid intelligence history counts or date.")
        previous = stamp
    if not document["days"] or previous != latest:
        raise ValueError("Intelligence history must end with the last successful collection.")
    if records is not None and collection["state"] == "current":
        if document["days"][-1] != aggregate(records, collection["data_updated_at"]):
            raise ValueError("Intelligence history does not match the current snapshot.")


def save_history(path, collection, records):
    if collection["state"] != "current":
        return
    collected_at = collection["data_updated_at"]
    stamp = utc_time(collected_at)
    prior = json.loads(path.read_text(encoding="utf-8"))["days"] if path.exists() else []
    earliest = stamp.date() - timedelta(days=RETENTION_DAYS - 1)
    days = [day for day in prior if earliest <= utc_time(day["collected_at"]).date() < stamp.date()]
    data = {"version": 1, "days": days + [aggregate(records, collected_at)]}
    validate_history(data, collection, records)
    atomic_write(path, json.dumps(data, indent=2) + "\n")
