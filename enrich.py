"""Offline enrichment and risk scoring. No external lookups.

Scoring is deliberately transparent and rule-based, so a reviewer can
reproduce every number:
- base score by IOC type
- +20 if the source is marked trusted in the demo data
- +15 per MITRE ATT&CK tag, capped at +30
- confidence (0-100 in the input) is carried through unchanged
Risk bands: >=70 High, >=40 Medium, otherwise Low.
"""

TYPE_SCORE = {"ip": 30, "domain": 30, "url": 35, "hash": 40}


def enrich(ioc):
    score = TYPE_SCORE.get(ioc["type"], 20)
    if ioc.get("source_trusted"):
        score += 20
    tags = ioc.get("mitre_tags") or []
    score += min(30, 15 * len(tags))
    score = min(100, score)
    band = "High" if score >= 70 else "Medium" if score >= 40 else "Low"
    return {
        **ioc,
        "risk_score": score,
        "risk_band": band,
        "enriched": True,
        "note": "Offline demo enrichment only; no live threat feed was queried.",
    }


def rank(iocs):
    return sorted((enrich(i) for i in iocs), key=lambda x: x["risk_score"], reverse=True)
