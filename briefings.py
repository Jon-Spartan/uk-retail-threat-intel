"""The evidence and output contract shared by generation and publication."""

import json
import re
import unicodedata
from datetime import datetime, timedelta
from urllib.parse import urlencode

from public_urls import validated_http_url


CVE_PATTERN = re.compile(r"\bCVE-[0-9]{4}-[0-9]{4,}\b", re.IGNORECASE)
KEV_PUBLISHER = "CISA KEV Catalog"
KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
PUBLISHER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9&(). /-]{0,79}")
SOURCE_FIELDS = {"id", "publisher", "title", "excerpt", "url", "kev_cve"}
LEGACY_STATUS_FIELDS = {"state", "checked_at", "generated_at"}
STATUS_FIELDS = LEGACY_STATUS_FIELDS | {"validated_at"}
BRIEFING_PREFIX = "AI-assisted selection of public-source evidence."
SOURCE_LIMIT = {"daily": 6, "weekly": 15}
SECTION_LIMIT = {
    "daily": {"facts": 3, "assessments": 2, "recommendations": 2},
    "weekly": {"facts": 6, "assessments": 4, "recommendations": 4},
}
SECTION_LABELS = {
    "facts": "Facts and attributed reporting",
    "assessments": "Assessments",
    "recommendations": "Recommendations",
}
TOPICS = (
    (r"\b(?:checkout|payment|skimming|magecart)\b", "payment or checkout security",
     "Review the relevance of the reported issue to payment and checkout controls."),
    (r"\b(?:credential stuffing|account takeover|stolen credentials|phishing|identity)\b",
     "identity or account security", "Review the relevance of the report to account and identity protections."),
    (r"\b(?:supply chain|logistics|warehouse|supplier|courier)\b", "supply-chain security",
     "Review the report against relevant supplier and logistics monitoring."),
    (r"\b(?:ransomware|extortion)\b", "ransomware or extortion",
     "Review the report alongside existing ransomware and extortion preparedness."),
    (r"\b(?:vulnerability|advisory|patch|security update)\b", "vulnerability or advisory reporting",
     "Review the original advisory and confirm product applicability before taking action."),
)


class BriefingValidationError(ValueError):
    """A briefing failed the publication contract."""


def require(condition, message):
    if not condition:
        raise BriefingValidationError(message)


def kev_article_url(cve):
    return KEV_URL + "?" + urlencode({"search_api_fulltext": cve})


def production_cve(value):
    return (isinstance(value, str) and CVE_PATTERN.fullmatch(value) is not None
            and value == value.upper() and int(value[4:8]) >= 1999)


def bounded_source_text(text, limit):
    if not isinstance(text, str):
        return ""
    text = "".join(char for char in text[:limit * 4] if unicodedata.category(char)[0] != "C" or char.isspace())
    return " ".join(text.split())[:limit].rstrip()


def snapshot_sources(articles, period):
    sources = []
    seen = set()
    for article in articles:
        url = validated_http_url(article.get("url"))
        publisher = article.get("source")
        title = bounded_source_text(article.get("title"), 240)
        if (not url or len(url) > 2048 or url in seen or not title
                or not isinstance(publisher, str) or not PUBLISHER_PATTERN.fullmatch(publisher)):
            continue
        kev_cve = None
        if publisher == KEV_PUBLISHER:
            cves = article.get("cves")
            if not isinstance(cves, list) or len(cves) != 1 or not production_cve(cves[0]):
                continue
            kev_cve = cves[0]
            if url != kev_article_url(kev_cve) or article.get("id") != "cisa-kev-" + kev_cve.lower().replace("-", "_"):
                continue
        seen.add(url)
        sources.append({
            "id": f"S{len(sources) + 1:02}",
            "publisher": publisher,
            "title": title,
            "excerpt": bounded_source_text(article.get("summary"), 350),
            "url": url,
            "kev_cve": kev_cve,
        })
        if len(sources) == SOURCE_LIMIT[period]:
            break
    return sources


def validate_sources(sources, period):
    require(isinstance(sources, list) and 1 <= len(sources) <= SOURCE_LIMIT[period],
            "Invalid briefing source count.")
    seen = set()
    for number, source in enumerate(sources, 1):
        require(isinstance(source, dict) and set(source) == SOURCE_FIELDS, "Invalid briefing source fields.")
        publisher, url = source["publisher"], source["url"]
        require(source["id"] == f"S{number:02}" and isinstance(publisher, str)
                and PUBLISHER_PATTERN.fullmatch(publisher) and validated_http_url(url)
                and len(url) <= 2048 and url not in seen, "Invalid briefing source identity.")
        require(bool(source["title"]) and source["title"] == bounded_source_text(source["title"], 240)
                and source["excerpt"] == bounded_source_text(source["excerpt"], 350),
                "Invalid briefing source evidence.")
        cve = source["kev_cve"]
        if publisher == KEV_PUBLISHER:
            require(production_cve(cve) and url == kev_article_url(cve), "Invalid KEV claim source.")
        else:
            require(cve is None, "CVE evidence must come from the CISA catalogue.")
        seen.add(url)


def candidate_items(sources):
    candidates = {section: {} for section in SECTION_LABELS}
    for source in sources:
        key = source["id"]
        if source["kev_cve"]:
            fact = f'CISA lists {source["kev_cve"]} in its Known Exploited Vulnerabilities Catalog.'
            assessment = "The catalogue entry merits review where the affected product is in use."
            recommendation = "Consult the CISA entry and vendor advisory to check applicability."
        else:
            evidence = source["title"] + " " + source["excerpt"]
            topic = next(((name, action) for pattern, name, action in TOPICS if re.search(pattern, evidence, re.I)),
                         None)
            if topic:
                name, recommendation = topic
                fact = f"The cited public report mentions {name}."
                assessment = f"The report is a monitoring input for {name}."
            else:
                fact = "The cited public report was selected for sector review."
                assessment = "Assess the report’s relevance against other sector sources."
                recommendation = "Read the original report and corroborate significant claims before acting."
        for section, label in zip(SECTION_LABELS, (fact, assessment, recommendation)):
            candidates[section][key] = label
    return candidates


def response_schema(sources, period):
    ids = [source["id"] for source in sources]
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(SECTION_LABELS),
        "properties": {
            section: {
                "type": "array",
                "items": {"type": "string", "enum": ids},
                "minItems": int(section == "facts"),
                "maxItems": min(len(ids), SECTION_LIMIT[period][section]),
            }
            for section in SECTION_LABELS
        },
    }


def validate_selection(value, sources, period):
    require(isinstance(value, dict) and set(value) == set(SECTION_LABELS), "Invalid briefing selection fields.")
    allowed = {source["id"] for source in sources}
    for section, selected in value.items():
        require(isinstance(selected, list) and int(section == "facts") <= len(selected) <= SECTION_LIMIT[period][section]
                and all(isinstance(source_id, str) and source_id in allowed for source_id in selected),
                "Invalid briefing source references.")
        require(len(selected) == len(set(selected)), "Duplicate briefing source reference.")
    fact_sources = set(value["facts"])
    require(all(set(value[section]) <= fact_sources for section in ("assessments", "recommendations")),
            "An assessment or recommendation has no corresponding fact.")


def parse_json(text, limit=64000):
    def unique(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs), "Duplicate briefing JSON property.")
        return result

    def invalid_constant(_):
        raise BriefingValidationError("Non-finite briefing value.")

    require(isinstance(text, str) and 0 < len(text) <= limit, "Invalid briefing JSON length.")
    try:
        return json.loads(text, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (json.JSONDecodeError, RecursionError) as error:
        raise BriefingValidationError("Invalid briefing JSON.") from error


def utc_time(value):
    try:
        parsed = datetime.fromisoformat(value) if isinstance(value, str) else None
        return parsed if parsed and parsed.utcoffset() == timedelta(0) else None
    except ValueError:
        return None


def validate_briefing(document, period):
    required = {"schema_version", "period", "coverage", "generated_at", "validated_at", "sources", "selection"}
    require(isinstance(document, dict) and set(document) == required, "Invalid briefing document fields.")
    require(type(document["schema_version"]) is int and document["schema_version"] == 1
            and document["period"] == period and document["coverage"] in ("current", "partial"),
            "Invalid briefing document version, period or coverage.")
    generated, validated = (utc_time(document[key]) for key in ("generated_at", "validated_at"))
    require(generated and validated and generated <= validated, "Invalid briefing timestamps.")
    validate_sources(document["sources"], period)
    validate_selection(document["selection"], document["sources"], period)


def render_briefing(document):
    candidates = candidate_items(document["sources"])
    lines = [BRIEFING_PREFIX]
    if document["coverage"] == "partial":
        lines.append("Collection was incomplete.")
    lines += [f'Generated {document["generated_at"]} · Validated {document["validated_at"]}']
    selection = document["selection"]
    for section, heading in SECTION_LABELS.items():
        if selection[section]:
            lines.extend(("", heading))
            lines.extend(f"- {candidates[section][key]} [{key}]" for key in selection[section])
    return "\n".join(lines) + "\n"


def render_summary(document):
    lines = [render_briefing(document), "Sources"]
    sources = {source["id"]: source for source in document["sources"]}
    for key in document["selection"]["facts"]:
        source = sources[key]
        lines.append(f'- [{key}] {source["publisher"]} <{source["url"]}>')
    return "\n".join(lines) + "\n"


def verify_retained_briefing(document, summary, status, period):
    validate_briefing(document, period)
    require(all(document[key] == status.get(key) for key in ("generated_at", "validated_at")),
            "Briefing and status timestamps disagree.")
    require(summary == render_summary(document), "Briefing summary differs from validated content.")


def load_briefing_pair(period, summary_path, evidence_path, status):
    document = parse_json(evidence_path.read_text(encoding="utf-8"))
    summary = summary_path.read_text(encoding="utf-8")
    verify_retained_briefing(document, summary, status, period)
    return document, summary


def discard_legacy_briefings(status, data_dir):
    for period in SOURCE_LIMIT:
        entry = status.get(period)
        if not isinstance(entry, dict) or set(entry) != LEGACY_STATUS_FIELDS:
            continue
        path = data_dir / f"{period}_briefing.json"
        require(not path.exists() and not path.is_symlink(), "A briefing has incompatible metadata.")
        (data_dir / f"{period}_summary.md").unlink(missing_ok=True)
        if period == "daily":
            (data_dir / "daily_summary_date.txt").unlink(missing_ok=True)
        status[period] = {"state": "unavailable", "checked_at": None, "generated_at": None, "validated_at": None}
