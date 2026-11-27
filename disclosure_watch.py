"""Triage official headlines for review without modifying publication data."""

import argparse
import json
import re
from pathlib import Path

from official_updates import validate_updates


DISCLOSURE = re.compile(
    r"\b(?:cyber(?:[ -]security)?[ -](?:incident|attack)|data (?:breach|incident)|ransomware (?:attack|incident))\b",
    re.IGNORECASE,
)
GENERIC = re.compile(r"\b(?:consultation|guidance|exercise|simulation|advisory)\b", re.IGNORECASE)


def candidates(snapshot):
    validate_updates(snapshot)
    return [
        {"id": story["id"], "source": story["source"], "date": story["published_at"], "url": story["url"]}
        for story in snapshot["stories"]
        if story["source"] != "nhs_cyber" and DISCLOSURE.search(story["title"]) and not GENERIC.search(story["title"])
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--count-only", action="store_true", help="Print just the candidate count for public CI logs.")
    args = parser.parse_args()
    rows = candidates(json.loads(args.snapshot.read_text(encoding="utf-8")))
    print(f"Disclosure candidates for manual review: {len(rows)}" if args.count_only else json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
