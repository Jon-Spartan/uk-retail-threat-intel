"""Versioned UK retail priority calculations and public evidence validation."""

import re
from datetime import date, datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlsplit

from briefings import KEV_PUBLISHER, production_cve
from public_urls import validated_http_url


CVE_CATALOG = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
EPSS_URL = "https://api.first.org/data/v1/epss"
MAX_CVE_LOOKUPS = 12
MAX_EPSS_LOOKUPS = 40
CVSS_VERSIONS = {"cvssV4_0": "4.0", "cvssV3_1": "3.1", "cvssV3_0": "3.0"}
ATTACK_CANONICAL = "https://attack.mitre.org/techniques/"
ATTACK_ID = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")
STORY_TOPICS = (
    ("ecom", r"\b(?:e[- ]?commerce|online shop|online store|checkout|payment gateway|skimming|magecart)\b"),
    ("pos", r"\b(?:point[- ]of[- ]sale|in-store payments?|payment terminals?|pin pads?)\b"),
    ("loyalty", r"\b(?:loyalty|loyalty programme|gift cards?|voucher fraud|customer accounts?)\b"),
    ("supply", r"\b(?:cold chain|warehouses?|retail logistics|distribution cent(?:re|er)s?|retail supply chain)\b"),
)
RETAIL_CONTEXT = re.compile(r"\b(?:retail(?:er)?s?|supermarkets?|high street|shopfronts?)\b", re.I)
UK_CONTEXT = re.compile(r"\b(?:uk|u\.k\.|united kingdom|british|great britain|england|scotland|wales|northern ireland)\b", re.I)
OFFICIAL_HOSTS = {
    KEV_PUBLISHER: {"cisa.gov", "www.cisa.gov"},
    "NCSC UK Advisories": {"ncsc.gov.uk", "www.ncsc.gov.uk"},
    "UK ICO Enforcement & News": {"ico.org.uk", "www.ico.org.uk"},
}
SPECIALIST = {
    "The Register Security (UK)", "Computer Weekly Security (UK)", "Krebs on Security",
    "The Hacker News", "BleepingComputer", "Dark Reading", "SecurityWeek", "Security Affairs",
}
CLASSIFICATION_FIELDS = {
    "version", "assessed_at", "kev_catalog_available", "vulnerabilities", "exploitation",
    "relevance", "source_tier", "confidence", "score", "components",
}
ARCHIVE_FIELDS = {"actor", "mitre", "mitre_id", "mitre_tactic", "mitre_name", "epss", "confidence"}


def cve_source_url(cve):
    year, sequence = cve.split("-")[1:]
    return f"{CVE_CATALOG}/{year}/{sequence[:-3].lstrip('0') or '0'}xxx/{cve}.json"


def cvss_severity(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW" if score > 0 else "NONE"


def within_range(value, end):
    return type(value) in (int, float) and 0 <= value <= end


def parse_cve_record(payload, cve):
    if (not isinstance(payload, dict) or payload.get("dataType") != "CVE_RECORD"
            or not isinstance(payload.get("dataVersion"), str)
            or not payload["dataVersion"].startswith("5.")):
        return None
    metadata = payload.get("cveMetadata")
    if not isinstance(metadata, dict) or metadata.get("cveId") != cve:
        return None
    state = metadata.get("state")
    if state == "REJECTED":
        return {"state": "rejected", "cvss": None}
    if state != "PUBLISHED":
        return None
    containers = payload.get("containers")
    cna = containers.get("cna") if isinstance(containers, dict) else None
    if not isinstance(cna, dict):
        return None
    # Prefer the primary CNA's base score. Third-party enrichment is not inferred as CNA evidence.
    metrics = cna.get("metrics")
    if isinstance(metrics, list):
        for key, version in CVSS_VERSIONS.items():
            scores = []
            for metric in metrics:
                value = metric.get(key) if isinstance(metric, dict) else None
                if (isinstance(value, dict) and value.get("version") == version
                        and isinstance(value.get("vectorString"), str)
                        and value["vectorString"].startswith(f"CVSS:{version}/")
                        and within_range(value.get("baseScore"), 10)):
                    scores.append(value["baseScore"])
            if scores:
                return {"state": "published", "cvss": {"version": version, "score": max(scores)}}
    return {"state": "published", "cvss": None}


def parse_epss(data, requested, assessed_on):
    observations = {}
    if not isinstance(data, list):
        return {}
    for entry in data:
        if not isinstance(entry, dict) or not isinstance(entry.get("cve"), str) or entry["cve"] not in requested:
            continue
        try:
            day = date.fromisoformat(entry["date"])
            if not 0 <= (assessed_on - day).days <= 7 or type(entry["epss"]) not in (str, int, float):
                continue
            score = float(entry["epss"])
        except (KeyError, ValueError, TypeError, OverflowError):
            continue
        if within_range(score, 1):
            observations.setdefault(entry["cve"], {}).setdefault(day, set()).add(score)
    result = {}
    for cve, dated_scores in observations.items():
        latest = max(dated_scores)
        scores = dated_scores[latest]
        if len(scores) == 1:
            result[cve] = {"probability": next(iter(scores)), "date": latest.isoformat()}
    return result


def attack_url(identifier):
    return ATTACK_CANONICAL + identifier.replace(".", "/") + "/"


class TechniqueLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.references = set()

    def handle_starttag(self, tag, attrs):
        if tag != "a" or len(self.references) >= 12:
            return
        for name, href in attrs:
            if name == "href" and validated_http_url(href) and href.startswith(ATTACK_CANONICAL):
                identifier = href.removeprefix(ATTACK_CANONICAL).removesuffix("/").replace("/", ".")
                if ATTACK_ID.fullmatch(identifier) and href in (attack_url(identifier), attack_url(identifier)[:-1]):
                    self.references.add(identifier)


def extract_attack_refs(html):
    parser = TechniqueLinks()
    if isinstance(html, str):
        parser.feed(html[:50000])
    return sorted(parser.references)


def retail_context(text):
    subsector = next((key for key, pattern in STORY_TOPICS if re.search(pattern, text, re.I)), "enterprise")
    if subsector == "enterprise" and not RETAIL_CONTEXT.search(text):
        return "unestablished", subsector
    return ("uk_direct" if UK_CONTEXT.search(text) else "sector"), subsector


def record_source_tier(record):
    publisher = record.get("source")
    url = validated_http_url(record.get("url"))
    if url and publisher in OFFICIAL_HOSTS and urlsplit(url).hostname in OFFICIAL_HOSTS[publisher]:
        return "authority"
    return "reporting" if publisher in SPECIALIST else "unassessed"


def calculate_priority(vulnerabilities, relevance, source_tier, timestamp, assessed_at):
    scores = [item["cvss"]["score"] for item in vulnerabilities if item["cvss"] is not None]
    probabilities = [item["epss"]["probability"] for item in vulnerabilities if item["epss"] is not None]
    max_cvss = max(scores, default=None)
    max_epss = max(probabilities, default=0)
    listed = any(item["kev"] is True for item in vulnerabilities)
    age = assessed_at.timestamp() - (timestamp or 0)
    freshness = 0
    if timestamp and 0 <= age <= 7 * 86400:
        freshness = 5 if age <= 86400 else 3 if age <= 3 * 86400 else 1
    confidence = "catalogue" if listed else "reference" if vulnerabilities else "unassessed"
    components = {
        "technical": round(max_cvss * 2) if max_cvss is not None else 0,
        "exploitation": 20 if listed else 0,
        "kev": 10 if listed else 0,
        "epss": 15 if max_epss >= 0.50 else 10 if max_epss >= 0.10 else 5 if max_epss >= 0.01 else 0,
        "retail": {"uk_direct": 20, "sector": 12, "unestablished": 0}[relevance],
        "source": {"authority": 5, "reporting": 3, "unassessed": 0}[source_tier],
        "confidence": {"catalogue": 5, "reference": 3, "unassessed": 0}[confidence],
        "freshness": freshness,
    }
    return cvss_severity(max_cvss), "confirmed" if listed else "unknown", confidence, components


def classify_record(record, kev_catalogue, cvss_records, epss, assessed_at):
    vulnerabilities = []
    for cve in record["reported_cves"]:
        primary = cvss_records.get(cve)
        listed = cve in kev_catalogue if kev_catalogue is not None else None
        if (primary and primary["state"] == "rejected") or not (primary or listed):
            continue
        vulnerabilities.append({
            "id": cve, "evidence": "cve_list" if primary else "kev_catalogue",
            "kev": listed, "cvss": primary["cvss"] if primary else None, "epss": epss.get(cve),
        })
    relevance, subsector = retail_context(record["title"] + " " + record.get("summary", ""))
    source_tier = record_source_tier(record)
    severity, exploitation, confidence, components = calculate_priority(
        vulnerabilities, relevance, source_tier, record.get("_timestamp"), assessed_at
    )
    record.update(severity=severity, subsector=subsector, cves=[item["id"] for item in vulnerabilities])
    record["classification"] = {
        "version": 1, "assessed_at": assessed_at.isoformat(), "kev_catalog_available": kev_catalogue is not None,
        "vulnerabilities": vulnerabilities, "exploitation": exploitation, "relevance": relevance,
        "source_tier": source_tier, "confidence": confidence, "score": sum(components.values()),
        "components": components,
    }
    return record


def qualifies_for_flash(record):
    evidence = record["classification"]
    return bool(record.get("is_new") and evidence["exploitation"] == "confirmed" and evidence["score"] >= 50)


def sanitize_archive(records):
    """Remove unverified legacy labels without rescoring historical evidence."""
    changed = False
    for record in records:
        if "classification" in record:
            continue
        if record.get("severity") == "UNKNOWN" and "reported_cves" in record and not ARCHIVE_FIELDS & record.keys():
            continue
        mentioned = record.get("reported_cves", record.get("cves", []))
        record["reported_cves"] = sorted({cve.upper() for cve in mentioned if isinstance(cve, str) and len(cve) <= 24
                                          and production_cve(cve.upper())})
        for field in ARCHIVE_FIELDS:
            record.pop(field, None)
        record["tags"] = [tag for tag in record.get("tags", []) if not tag.lower().startswith("actor:")
                          and tag not in ("Active Exploit", "Known exploitation", "Ransomware Campaign")]
        _, subsector = retail_context(record["title"] + " " + (record.get("summary") or ""))
        record.update(severity="UNKNOWN", subsector=subsector, cves=[], is_new=False, is_flash=False, attack_refs=[])
        record["advisory"] = "Read the original source to confirm relevance and applicability."
        changed = True
    return changed


def classification_is_valid(record):
    classed = record["classification"]
    if (not isinstance(classed, dict) or set(classed) != CLASSIFICATION_FIELDS
            or type(classed["version"]) is not int or classed["version"] != 1):
        return False
    try:
        clock = datetime.fromisoformat(classed["assessed_at"])
        if clock.utcoffset() != timezone.utc.utcoffset(None):
            return False
    except (ValueError, TypeError):
        return False
    catalogue = classed["kev_catalog_available"]
    items = classed["vulnerabilities"]
    if not isinstance(catalogue, bool) or not isinstance(items, list) or len(items) > 100:
        return False
    for item in items:
        if (not isinstance(item, dict) or set(item) != {"id", "evidence", "kev", "cvss", "epss"}
                or not production_cve(item["id"]) or item["evidence"] not in ("cve_list", "kev_catalogue")
                or (not isinstance(item["kev"], bool) if catalogue else item["kev"] is not None)
                or (item["evidence"] == "kev_catalogue" and (item["kev"] is not True or item["cvss"] is not None))):
            return False
        cvss = item["cvss"]
        if cvss is not None and (not isinstance(cvss, dict) or set(cvss) != {"score", "version"}
                                 or cvss["version"] not in CVSS_VERSIONS.values() or not within_range(cvss["score"], 10)):
            return False
        epss = item["epss"]
        if epss is not None and (not isinstance(epss, dict) or set(epss) != {"probability", "date"}
                                 or parse_epss([{"cve": item["id"], "epss": epss["probability"], "date": epss["date"]}],
                                               {item["id"]}, clock.date()).get(item["id"]) != epss):
            return False
    ids = [item["id"] for item in items]
    if len(set(ids)) != len(ids) or ids != record.get("cves") or not set(ids) <= set(record.get("reported_cves", [])):
        return False
    relevance, subsector = retail_context(record["title"] + " " + (record.get("summary") or ""))
    source_tier = record_source_tier(record)
    severity, exploitation, confidence, components = calculate_priority(
        items, relevance, source_tier, record.get("_timestamp"), clock
    )
    points = classed["components"]
    return (isinstance(points, dict) and all(type(value) is int for value in points.values())
            and type(classed["score"]) is int and classed["score"] == sum(components.values())
            and points == components and record.get("severity") == severity and record.get("subsector") == subsector
            and classed["confidence"] == confidence
            and classed["exploitation"] == exploitation and classed["relevance"] == relevance
            and classed["source_tier"] == source_tier
            and (not record.get("is_flash") or qualifies_for_flash(record)))
