"""Threat Intelligence Platform - CLI. Usage: python3 main.py [--input X] [--output Y]"""
import argparse
import json
from pathlib import Path

from enrich import rank
from ioc_collector import load_iocs


def main():
    parser = argparse.ArgumentParser(description="Collect and enrich IOCs (demo data only).")
    parser.add_argument("--input", default="data/sample_iocs.json")
    parser.add_argument("--output", default="output/report.json")
    args = parser.parse_args()

    valid, invalid = load_iocs(args.input)
    ranked = rank(valid)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"iocs": ranked, "invalid": invalid}, indent=2))

    md = ["# Threat Intelligence Report", "", f"Valid IOCs: {len(ranked)} | Invalid: {len(invalid)}", ""]
    for ioc in ranked:
        md.append(f"- [{ioc['risk_band']}] {ioc['type']}: {ioc['value']} (score {ioc['risk_score']}, "
                  f"tags: {', '.join(ioc.get('mitre_tags') or ['-'])})")
    (out.parent / "report.md").write_text("\n".join(md) + "\n")

    print(f"Valid: {len(ranked)}  Invalid: {len(invalid)}  Report: {out} and output/report.md")
    for ioc in ranked:
        print(f"  [{ioc['risk_band']}] {ioc['type']}: {ioc['value']} score={ioc['risk_score']}")


if __name__ == "__main__":
    main()
