"""PurpleLens test suite. Sigma-backend tests run fully offline (vendored
rules only). soc-parallax-backend tests are split: graceful-degradation
behavior is tested unconditionally; the real live-checkout integration
check only runs if SOC_PARALLAX_PATH is set, skipped otherwise — so a
fresh clone of this repo (or CI without that env var) still passes cleanly
without needing another person's private repo checked out locally.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from purplelens import navigator, sigma_adapter, soc_parallax_adapter
from purplelens.techniques import SIGMA_TESTED, SOC_PARALLAX_TESTED, TECHNIQUES

# -- Sigma matcher / adapter (fully offline, vendored rules only) -----------

@pytest.mark.parametrize("technique_id", sorted(SIGMA_TESTED))
def test_sigma_detects_its_own_vendored_technique(technique_id):
    result = sigma_adapter.evaluate(technique_id, TECHNIQUES[technique_id].fields)
    assert result["available"] is True
    assert result["detected"] is True
    assert result["matched_rule"]


def test_sigma_reports_unavailable_not_a_false_miss_for_untested_technique():
    """A technique with no vendored Sigma rule must report available=False,
    not detected=False — those mean different things (never tested vs.
    tested and Sigma missed it), and conflating them would silently turn
    'we haven't vendored a rule for this' into 'Sigma has a coverage gap'."""
    untested = set(TECHNIQUES) - SIGMA_TESTED
    assert untested, "expected at least one technique with no vendored Sigma rule"
    for tid in untested:
        result = sigma_adapter.evaluate(tid, TECHNIQUES[tid].fields)
        assert result["available"] is False
        assert result["detected"] is False


def test_sigma_does_not_false_positive_across_unrelated_techniques():
    """Each Sigma-tested rule's synthetic event must not accidentally
    trigger a DIFFERENT vendored rule for a different technique."""
    for tid in SIGMA_TESTED:
        for other_tid in SIGMA_TESTED - {tid}:
            result = sigma_adapter.evaluate(other_tid, TECHNIQUES[tid].fields)
            assert result["detected"] is False, (
                f"{tid}'s event unexpectedly matched {other_tid}'s rule too")


def test_sigma_contains_all_modifier_requires_every_value_present():
    """Regression guard for SigmaAllModifier (the |contains|all combo) —
    added specifically because the LSASS-dump rule uses it and the matcher
    initially rejected it as an unsupported modifier (it isn't; it's a
    value-linking concern already handled via item.value_linking, not a
    per-value comparison one)."""
    fields = dict(TECHNIQUES["T1003"].fields)
    fields["CommandLine"] = "some_tool.exe lsass"  # 'lsass' present, '.dmp' is not
    result = sigma_adapter.evaluate("T1003", fields)
    assert result["available"] is True
    assert result["detected"] is False, "must require ALL of ['lsass', '.dmp'], not just one"


def test_sigma_nested_parens_and_all_of_wildcard_quantifier():
    """Regression guard for the run-key rule's condition:
    'selection_target and (selection_suspicious_paths_1 or (all of
    selection_suspicious_paths_user_*)) and not 1 of filter_main_* and not
    1 of filter_optional_*' — nested parens plus an 'all of pattern*'
    quantifier, the most structurally complex condition PurpleLens's
    parser handles among the vendored fixtures."""
    result = sigma_adapter.evaluate("T1547", TECHNIQUES["T1547"].fields)
    assert result["available"] is True
    assert result["detected"] is True
    # Same registry key, but Details points somewhere ordinary — should miss.
    fields = dict(TECHNIQUES["T1547"].fields)
    fields["Details"] = r"C:\Program Files\LegitApp\legitapp.exe"
    result = sigma_adapter.evaluate("T1547", fields)
    assert result["detected"] is False


def test_sigma_condition_exclusion_filter_suppresses_legit_system_activity():
    """Regression guard for the 'not 1 of filter_*' exclusion path
    specifically — a SYSTEM-run scheduled task must not fire the rule that
    a user-run one correctly does."""
    fields = dict(TECHNIQUES["T1053"].fields)
    fields["User"] = r"NT AUTHORITY\SYSTEM"
    result = sigma_adapter.evaluate("T1053", fields)
    assert result["available"] is True
    assert result["detected"] is False


# -- soc-parallax adapter: graceful degradation (always runs) ---------------

def test_soc_parallax_adapter_unavailable_without_path(monkeypatch):
    monkeypatch.delenv("SOC_PARALLAX_PATH", raising=False)
    monkeypatch.setattr(soc_parallax_adapter, "_rules_mod", None)
    monkeypatch.setattr(soc_parallax_adapter, "_import_error", None)
    result = soc_parallax_adapter.evaluate("T1059.001", TECHNIQUES["T1059.001"].fields)
    assert result["available"] is False
    assert result["error"] == "SOC_PARALLAX_PATH not set"


def test_soc_parallax_adapter_unavailable_on_bad_path(monkeypatch, tmp_path):
    monkeypatch.setenv("SOC_PARALLAX_PATH", str(tmp_path / "does-not-exist"))
    monkeypatch.setattr(soc_parallax_adapter, "_rules_mod", None)
    monkeypatch.setattr(soc_parallax_adapter, "_import_error", None)
    assert soc_parallax_adapter.is_available() is False


# -- soc-parallax adapter: real integration (only if the checkout exists) --

_SPX_PATH = os.getenv("SOC_PARALLAX_PATH")


@pytest.mark.skipif(not _SPX_PATH, reason="SOC_PARALLAX_PATH not set — skipping live check")
@pytest.mark.parametrize("technique_id", sorted(SOC_PARALLAX_TESTED))
def test_soc_parallax_detects_its_own_covered_technique(technique_id):
    result = soc_parallax_adapter.evaluate(technique_id, TECHNIQUES[technique_id].fields)
    assert result["available"] is True
    assert result["detected"] is True, (
        f"{technique_id}: soc-parallax's own rules.py + mitre.yaml no longer agree "
        f"with PurpleLens's synthetic event for it — check for drift")


# -- navigator layer generation (offline, synthetic result dicts) ----------

def _result(available, detected, rule=None, tag=None):
    return {"available": available, "detected": detected, "matched_rule": rule,
           "matched_tag": tag, "error": None}


def test_navigator_classifies_both_backends_detecting():
    coverage = {"T1000": {"description": "x",
                          "soc_parallax": _result(True, True, "r1"),
                          "sigma": _result(True, True, "r2")}}
    layer = navigator.build_layer(coverage)
    assert layer["techniques"][0]["color"] == navigator._COLORS["both"][0]


def test_navigator_classifies_neither_tested():
    coverage = {"T1000": {"description": "x",
                          "soc_parallax": _result(False, False),
                          "sigma": _result(False, False)}}
    layer = navigator.build_layer(coverage)
    assert layer["techniques"][0]["color"] == navigator._COLORS["neither_tested"][0]


def test_navigator_classifies_tested_but_missed_by_both():
    coverage = {"T1000": {"description": "x",
                          "soc_parallax": _result(True, False),
                          "sigma": _result(True, False)}}
    layer = navigator.build_layer(coverage)
    assert layer["techniques"][0]["color"] == navigator._COLORS["tested_missed"][0]


def test_navigator_layer_matches_v4_5_schema_shape():
    coverage = {"T1000": {"description": "x",
                          "soc_parallax": _result(True, True, "r1"),
                          "sigma": _result(False, False)}}
    layer = navigator.build_layer(coverage)
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert layer["techniques"][0]["techniqueID"] == "T1000"
    assert isinstance(layer["techniques"][0]["score"], (int, float))
    assert layer["techniques"][0]["color"].startswith("#")
    assert len(layer["legendItems"]) == 5


# -- coverage-completeness meta-checks --------------------------------------

def test_every_sigma_tested_technique_actually_has_a_vendored_rule():
    """Catches drift if SIGMA_TESTED claims a technique that no longer has
    a matching vendored rule file (e.g. a rule was removed but the set
    wasn't updated)."""
    for tid in SIGMA_TESTED:
        assert sigma_adapter.rules_for_technique(tid), (
            f"{tid} is listed in SIGMA_TESTED but no vendored rule is tagged for it")
