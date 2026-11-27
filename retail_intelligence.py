"""Validate the reviewed public retail register before Pages staging."""

import re
from datetime import date, datetime, timezone
from urllib.parse import urlsplit

from public_urls import validated_http_url

REGISTER = "assets/retail-intelligence.json"
PUBLISHERS = {
    "NCSC": ("www.ncsc.gov.uk", r"/guidance/[a-z0-9-]+", "first_party"),
    "The Register": ("www.theregister.com", r"/(?:cyber-crime|security)/[0-9]{4}/[0-9]{2}/[0-9]{2}/[a-z0-9-]+/[0-9]+", "attributed"),
    "Cleverbridge": ("grow.cleverbridge.com", r"/incident-update", "first_party"),
    "McDonald’s Japan": ("www.mcdonalds.co.jp", r"/company/info/[0-9]+[a-z].html|/company/info/[0-9]+[a-z]/", "first_party"),
}
CATEGORIES = set(("ransomware credential_theft phishing supply_chain exploitation ecommerce_fraud "
                  "payment_card data_breach disruption insider ai_enabled unclassified").split())
FUNCTIONS = set(("ecommerce payments physical_stores logistics supply_chain customer_data contact_centres "
                 "enterprise loyalty").split())
SUPPLIERS = set("payment logistics saas managed_service ecommerce marketing customer_service cloud".split())
FIELDS = set(("id kind title organisation organisation_type geography status relevance confidence supplier_type categories "
              "functions seasonal initial_access impact exposure lesson timeline").split())


def require(condition, message):
    if not condition:
        raise ValueError(f"Retail register: {message}")


def calendar_date(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value), "invalid public date.")
    return date.fromisoformat(value)


def bounded_text(value, limit):
    return (isinstance(value, str) and 0 < len(value) <= limit and value == " ".join(value.split())
            and not any(character in "<>" or ord(character) < 32 for character in value))


def validate_register(document):
    require(isinstance(document, dict) and set(document) == {"version", "reviewed_on", "records"}
            and type(document["version"]) is int and document["version"] == 1, "invalid envelope.")
    reviewed = calendar_date(document["reviewed_on"])
    require(reviewed <= datetime.now(timezone.utc).date(), "review date is in the future.")
    records = document["records"]
    require(isinstance(records, list) and len(records) <= 250, "invalid record list.")
    identifiers, owner_by_url = set(), {}
    for record in records:
        require(isinstance(record, dict) and set(record) == FIELDS, "unexpected record fields.")
        identifier = record["id"]
        require(isinstance(identifier, str) and re.fullmatch(r"retail-[0-9]{4,8}", identifier)
                and identifier not in identifiers, "invalid or duplicate ID.")
        identifiers.add(identifier)
        for field in ("title", "organisation", "organisation_type", "lesson"):
            require(bounded_text(record[field], 350), "invalid public text.")
        for field in ("geography", "initial_access", "impact", "exposure"):
            require(record[field] is None or bounded_text(record[field], 350), "invalid optional public text.")
        require(record["kind"] in ("incident", "advisory", "campaign", "development")
                and record["status"] in ("investigating", "resolved", "reported", "guidance", "unknown")
                and record["relevance"] in ("uk_direct", "sector") and record["confidence"] in ("first_party", "attributed")
                and (record["supplier_type"] is None or record["supplier_type"] in tuple(SUPPLIERS))
                and type(record["seasonal"]) is bool, "invalid classification.")
        for field, taxonomy in (("categories", CATEGORIES), ("functions", FUNCTIONS)):
            values = record[field]
            require(isinstance(values, list) and all(isinstance(value, str) and value in taxonomy for value in values)
                    and len(values) == len(set(values)), "invalid taxonomy values.")
        timeline = record["timeline"]
        require(isinstance(timeline, list) and 1 <= len(timeline) <= 40, "invalid timeline.")
        prior = date.min
        first_party = False
        for index, entry in enumerate(timeline):
            require(isinstance(entry, dict) and set(entry) == {"date", "kind", "publisher", "url", "summary"},
                    "invalid evidence fields.")
            when = calendar_date(entry["date"])
            require(prior <= when <= reviewed and (entry["kind"] == "report" if index == 0 else
                    entry["kind"] in ("update", "correction", "evidence_review")), "invalid timeline order.")
            prior = when
            publisher = entry["publisher"]
            require(isinstance(publisher, str) and publisher in PUBLISHERS and bounded_text(entry["summary"], 350),
                    "unapproved or invalid evidence.")
            host, path, tier = PUBLISHERS[publisher]
            url = entry["url"]
            require(validated_http_url(url), "unsafe evidence URL.")
            parts = urlsplit(url)
            require(parts.scheme == "https" and parts.netloc == host and not parts.query and not parts.fragment
                    and re.fullmatch(path, parts.path), "unapproved evidence URL.")
            require(owner_by_url.setdefault(url, identifier) == identifier, "evidence already belongs to another record.")
            first_party |= tier == "first_party"
        require(record["confidence"] != "first_party" or first_party, "first-party evidence required.")
        if record["kind"] != "incident":
            require(all(record[field] is None for field in ("initial_access", "impact", "exposure")),
                    "incident fields on a non-incident.")
