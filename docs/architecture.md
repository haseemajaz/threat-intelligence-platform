# Architecture - Threat Intelligence Platform

## Pipeline

```
sample_iocs.json
  -> ioc_collector.load_iocs()   validate type/value, split valid/invalid
  -> enrich.rank()               offline score + MITRE tags + risk band
  -> main.py                     write output/report.json + output/report.md
```

## Design decisions

- **Offline only.** No external threat feed, API key, or network call.
  A production version would swap `enrich.py` for a feed client
  (e.g. AlienVault OTX, MISP) behind the same `enrich()` interface.
- **Transparent scoring.** Rules live in `enrich.py` with fixed weights,
  so any score can be explained line by line. No black-box model.
- **Validation first.** Bad IOCs are reported in the `invalid` list,
  never silently dropped, so the report is auditable.
- **MITRE ATT&CK tags** are stored as plain strings (e.g. `T1071.001`),
  which keeps the demo portable and lets a reviewer map each IOC to a
  technique without a live ATT&CK lookup.

## What to extend next

1. Add a feed adapter (OTX/MISP) implementing `enrich()`.
2. Add deduplication and first-seen / last-seen tracking in SQLite.
3. Add a small Flask/FastAPI read-only API over `output/report.json`.
