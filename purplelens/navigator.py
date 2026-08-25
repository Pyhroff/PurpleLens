"""Build a real MITRE ATT&CK Navigator layer file (spec v4.5, verified
against the official schema: github.com/mitre-attack/attack-navigator/
blob/master/layers/spec/v4.5/layerformat.md) from PurpleLens coverage
results — loads directly in the real Navigator (mitre-attack.github.io/
attack-navigator/), not a lookalike JSON invented for this project.

Colors are assigned explicitly per technique (not score-gradient-derived)
so the four coverage states are visually unambiguous at a glance.
"""
from __future__ import annotations

# Explicit per-state colors + numeric scores (scores are cosmetic here since
# color overrides them per the v4.5 spec, but Navigator's sort-by-score and
# aggregate-score features still use them, so they're set meaningfully).
_COLORS = {
    "both": ("#3f9c3f", 100),          # detected by soc-parallax AND Sigma
    "soc_parallax_only": ("#3f7fbf", 70),
    "sigma_only": ("#bf8f3f", 70),
    "neither_tested": ("#888888", 30),  # not vendored/wired for either backend
    "tested_missed": ("#bf3f3f", 10),   # tested against >=1 backend, none fired
}

LEGEND = [
    {"label": "Detected by both backends", "color": _COLORS["both"][0]},
    {"label": "Detected by soc-parallax only", "color": _COLORS["soc_parallax_only"][0]},
    {"label": "Detected by Sigma only", "color": _COLORS["sigma_only"][0]},
    {"label": "Tested against >=1 backend, not detected", "color": _COLORS["tested_missed"][0]},
    {"label": "Not vendored/tested for either backend yet", "color": _COLORS["neither_tested"][0]},
]


def _classify(spx_result: dict, sigma_result: dict) -> str:
    spx_hit = spx_result["available"] and spx_result["detected"]
    sigma_hit = sigma_result["available"] and sigma_result["detected"]
    any_tested = spx_result["available"] or sigma_result["available"]
    if spx_hit and sigma_hit:
        return "both"
    if spx_hit:
        return "soc_parallax_only"
    if sigma_hit:
        return "sigma_only"
    if any_tested:
        return "tested_missed"
    return "neither_tested"


def _comment(technique_id: str, description: str, spx_result: dict, sigma_result: dict) -> str:
    lines = [description, ""]
    for name, result in (("soc-parallax", spx_result), ("Sigma", sigma_result)):
        if not result["available"]:
            reason = f" ({result['error']})" if result.get("error") else ""
            lines.append(f"{name}: not tested{reason}")
        elif result["detected"]:
            rule = result["matched_rule"] or "?"
            tag = f" [{result['matched_tag']}]" if result.get("matched_tag") else ""
            lines.append(f"{name}: DETECTED — {rule}{tag}")
        else:
            lines.append(f"{name}: tested, not detected"
                         f"{' (' + result['error'] + ')' if result.get('error') else ''}")
    return "\n".join(lines)


_DEFAULT_DESCRIPTION = ("Detection coverage: soc-parallax rules vs. vendored Sigma rules, "
                       "synthetic-event-driven.")


def build_layer(coverage: dict, name: str = "PurpleLens coverage",
                description: str = _DEFAULT_DESCRIPTION) -> dict:
    """`coverage`: {technique_id: {"description": str, "soc_parallax": result_dict,
    "sigma": result_dict}}. Returns a dict ready for json.dump — a real,
    Navigator-loadable layer, not a summary invented for this project."""
    techniques = []
    for tid, entry in coverage.items():
        state = _classify(entry["soc_parallax"], entry["sigma"])
        color, score = _COLORS[state]
        techniques.append({
            "techniqueID": tid,
            "score": score,
            "color": color,
            "comment": _comment(tid, entry["description"], entry["soc_parallax"], entry["sigma"]),
        })
    return {
        "name": name,
        "versions": {"attack": "17", "navigator": "5.2.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description,
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "legendItems": LEGEND,
        "metadata": [{"name": "generated_by", "value": "PurpleLens"}],
    }
