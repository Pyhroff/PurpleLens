"""Sigma backend: load vendored real Sigma rules, find which are tagged for
a given technique, evaluate them against a synthetic event.

Technique-ID granularity note: SigmaHQ rules are commonly tagged with
sub-techniques (e.g. "attack.t1053.005"), while PurpleLens's curated
technique list (techniques.py) intentionally uses parent-level IDs (T1053)
to stay aligned with how soc-parallax's mitre.yaml declares coverage. A
rule tagged for a sub-technique of the one being queried counts as a match
for the parent — that's a real, worth-knowing granularity mismatch between
detection systems, not something to silently paper over, so `evaluate()`
reports the exact matched tag alongside the pass/fail result.
"""
from __future__ import annotations

from pathlib import Path

from sigma.collection import SigmaCollection

from .sigma_matcher import rule_matches

RULES_DIR = Path(__file__).resolve().parent.parent / "sigma_rules"


def _load_rules() -> list:
    rules = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        rules.extend(SigmaCollection.from_yaml(path.read_text(encoding="utf-8")).rules)
    return rules


def _attack_tags(rule) -> list[str]:
    return [t.name for t in rule.tags if t.namespace == "attack" and t.name.startswith("t")]


def _tag_covers_technique(tag: str, technique_id: str) -> bool:
    """tag is e.g. 't1053.005' (lowercase, no leading T); technique_id is
    e.g. 'T1053'. A sub-technique tag counts as covering its parent."""
    target = technique_id.lower().lstrip("t")
    tag_id = tag.lstrip("t")
    return tag_id == target or tag_id.startswith(target + ".")


def rules_for_technique(technique_id: str, rules: list | None = None) -> list:
    rules = rules if rules is not None else _load_rules()
    return [r for r in rules
           if any(_tag_covers_technique(t, technique_id) for t in _attack_tags(r))]


def evaluate(technique_id: str, fields: dict, rules: list | None = None) -> dict:
    """Returns {'available': bool, 'detected': bool, 'matched_rule': str|None,
    'matched_tag': str|None, 'error': str|None}. 'available' is False when no
    vendored rule is tagged for this technique at all — distinct from
    'available and checked, but didn't fire', so a caller can tell 'we never
    tested this' from 'we tested it and Sigma missed it'."""
    candidates = rules_for_technique(technique_id, rules)
    if not candidates:
        return {"available": False, "detected": False, "matched_rule": None,
                "matched_tag": None, "error": None}
    for rule in candidates:
        try:
            if rule_matches(rule, fields):
                tag = next(t for t in _attack_tags(rule) if _tag_covers_technique(t, technique_id))
                return {"available": True, "detected": True, "matched_rule": rule.title,
                        "matched_tag": tag, "error": None}
        except NotImplementedError as e:
            return {"available": True, "detected": False, "matched_rule": rule.title,
                    "matched_tag": None, "error": str(e)}
    return {"available": True, "detected": False, "matched_rule": None,
           "matched_tag": None, "error": None}
