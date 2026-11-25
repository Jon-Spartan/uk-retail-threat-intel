# UK retail intelligence scoring

Version 1 ranks public-source reports for UK retail triage. Its 0–100 priority score expresses the available evidence for monitoring. Organisation-specific exposure, risk, compliance and security posture require separate evidence.

| Factor | Maximum | Calculation |
| --- | --- | --- |
| Technical severity | 20 | Twice the highest verified CVSS base score, rounded to the nearest integer with ties rounded to even. |
| Confirmed exploitation | 20 | Twenty points when a referenced CVE is in the collected CISA KEV catalogue. This confirms known exploitation of the vulnerability. |
| CISA KEV | 10 | Ten additional points for the catalogue match. This makes the model’s deliberate emphasis on confirmed exploitation visible. |
| EPSS | 15 | Highest eligible FIRST probability across verified CVEs earns 15 points at 50% or above, 10 at 10% or above, 5 at 1% or above, and zero below 1%. |
| UK retail relevance | 20 | Twenty points for both explicit UK context and a retail term or operational topic. Twelve for the retail cue alone. |
| Source credibility | 5 | Five for a configured official publisher and matching official hostname, three for configured specialist reporting, and zero for unassessed publishers. |
| Evidence confidence | 5 | Five for a matching catalogue entry, three for a verified CVE reference, and zero when evidence is unassessed. This assesses confidence in the traceable reference. |
| Source-date freshness | 5 | Five points at 24 hours or less, three at 72 hours or less, one at seven days or less, and zero for older, future or unavailable dates. |

The total is the sum of the eight factors. Missing data contributes zero points and the remaining factors keep their original weights. A zero contribution may reflect unavailable evidence. The dashboard shows technical severity, priority, confidence, the factor breakdown, and available underlying CVE evidence separately. The feed sorts by priority, newness and source date. A new report is eligible for a flash alert when exploitation is confirmed and its priority is at least 50.

## Dashboard shortlist

Start here uses the existing score after ordering records by declared product matches and newness since the previous browser visit. Product names come from the CISA catalogue and entries in the primary CVE record that declare an affected version or default status. A product match identifies a version-checking lead.

## Evidence and coverage

- Article CVE mentions are kept separately from verified IDs. Technical severity comes from the highest valid primary CNA base score among the verified CVEs. Within a CVE the preferred versions are 4.0, 3.1 and 3.0 in that order, with the highest valid score used within the chosen version. A rejected CVE record suppresses the corresponding technical evidence even when the catalogue contains that identifier. Unrated articles show CVSS as unassessed. The collector attempts at most 12 CVE List lookups per run and prioritises KEV matches. [Official CVE List](https://github.com/CVEProject/cvelistV5) [FIRST CVSS specification](https://www.first.org/cvss/specification-document)
- CISA catalogue membership is checked against the full collected catalogue, independent of the seven-day publication window. The evidence fields distinguish a listed CVE, a CVE absent from the collected list and unavailable catalogue data. Catalogue absence leaves exploitation unknown. [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- EPSS uses one bounded lookup for up to 40 verified CVEs per run. Probabilities and their source dates are retained per CVE. Forecasts dated more than seven days before the assessment or dated in the future are excluded. The probability estimates observed exploitation activity over the next 30 days. EPSS is provided by FIRST and Empirical Security. [FIRST EPSS data and attribution](https://www.first.org/epss/data)
- Relevance is a text cue drawn from the published headline and bounded excerpt. Sector categories use explicit checkout, point-of-sale, loyalty and logistics terms. Source classification and relevance are separate. Keyword intake still selects reports for review, including general enterprise items. None of those intake terms assigns a technical severity.
- Threat actor labels and inferred ATT&CK mappings are excluded. The matrix counts explicit links in feed entries to canonical MITRE technique pages. A citation means the source linked to a technique. Verified adversary behaviour requires separate evidence. [MITRE ATT&CK guidance](https://attack.mitre.org/resources/pre-introduction/)
- The imported snapshot is unassessed. Older labels were removed from the historical data without refreshing its collection timestamp.
