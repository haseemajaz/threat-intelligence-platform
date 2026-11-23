# 05 - Threat Intelligence Platform

Collect, enrich, and prioritise Indicators of Compromise (IOCs) from local demo data.

## What it does

- Loads IOCs (IP, domain, URL, file hash) from `data/sample_iocs.json`
- Validates and normalises each IOC
- Enriches it with a local, offline reputation score and a MITRE ATT&CK-style
  tag (no external API, no paid service, no live lookup)
- Ranks IOCs by risk score and writes a report to `output/report.json`
  and a readable `output/report.md`

## What an employer sees

A small, honest pipeline: ingest -> validate -> enrich -> rank -> report.
The scoring rules are in plain code in `enrich.py`, so a reviewer can see
exactly why an IOC scored high. All data is invented demo data.

## How to run

```bash
cd 05-threat-intelligence-platform
python3 main.py
# or: python3 main.py --input data/sample_iocs.json --output output/report.json
```

Requires Python 3.10+. No dependencies, standard library only.

## Files

- `main.py` - CLI entry point
- `ioc_collector.py` - load and validate IOCs
- `enrich.py` - offline enrichment and risk scoring
- `data/sample_iocs.json` - 8 demo IOCs (invented, not real threats)
- `docs/architecture.md` - design notes
