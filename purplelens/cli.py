"""PurpleLens CLI: run the curated technique library against both backends,
print a summary table, and write a real ATT&CK Navigator layer file.

Usage:
    python -m purplelens.cli [--out layer.json]

    # to also enable the soc-parallax backend:
    SOC_PARALLAX_PATH=/path/to/soc-parallax python -m purplelens.cli
"""
from __future__ import annotations

import argparse
import json

from . import navigator, sigma_adapter, soc_parallax_adapter
from .techniques import TECHNIQUES


def run_coverage() -> dict:
    sigma_rules = sigma_adapter._load_rules()
    coverage = {}
    for tid, ev in TECHNIQUES.items():
        coverage[tid] = {
            "description": ev.description,
            "soc_parallax": soc_parallax_adapter.evaluate(tid, ev.fields),
            "sigma": sigma_adapter.evaluate(tid, ev.fields, rules=sigma_rules),
        }
    return coverage


def print_summary(coverage: dict) -> None:
    print(f"{'Technique':<12} {'soc-parallax':<16} {'Sigma':<16} Description")
    print("-" * 90)
    for tid, entry in coverage.items():
        def cell(r):
            if not r["available"]:
                return "n/a"
            return "DETECTED" if r["detected"] else "missed"
        print(f"{tid:<12} {cell(entry['soc_parallax']):<16} {cell(entry['sigma']):<16} "
             f"{entry['description'][:50]}")

    spx_available = sum(1 for e in coverage.values() if e["soc_parallax"]["available"])
    spx_detected = sum(1 for e in coverage.values() if e["soc_parallax"]["detected"])
    sig_available = sum(1 for e in coverage.values() if e["sigma"]["available"])
    sig_detected = sum(1 for e in coverage.values() if e["sigma"]["detected"])
    print("-" * 90)
    print(f"soc-parallax: {spx_detected}/{spx_available} tested-and-detected "
         f"({len(coverage) - spx_available} not tested for this backend)")
    print(f"Sigma:        {sig_detected}/{sig_available} tested-and-detected "
         f"({len(coverage) - sig_available} not tested for this backend)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="purplelens_layer.json",
                       help="ATT&CK Navigator layer output path (default: purplelens_layer.json)")
    args = parser.parse_args()

    coverage = run_coverage()
    print_summary(coverage)

    layer = navigator.build_layer(coverage)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(layer, fh, indent=2)
    print(f"\nATT&CK Navigator layer written to {args.out}")
    print("Load it at https://mitre-attack.github.io/attack-navigator/ "
         "(Open Existing Layer -> Upload)")


if __name__ == "__main__":
    main()
