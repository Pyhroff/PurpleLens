"""soc-parallax backend: optional, path-configurable — imports the real
app.detect.signals.rules / app.detect.mitre modules from a local
Pyhroff/soc-parallax checkout if one is available, rather than vendoring a
copy that would silently drift out of sync with the real source.

Not a hard dependency: PurpleLens works standalone on the Sigma backend
alone. Point SOC_PARALLAX_PATH (env var) at a local soc-parallax checkout
(the folder containing `backend/`) to enable this second backend; if unset
or the import fails, `evaluate()` reports itself unavailable rather than
raising, so a coverage run degrades gracefully to Sigma-only.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

_rules_mod = None
_mitre_mod = None
_event_from_record = None
_import_error: str | None = None


def _try_import():
    global _rules_mod, _mitre_mod, _event_from_record, _import_error
    if _rules_mod is not None or _import_error is not None:
        return  # already attempted
    path = os.getenv("SOC_PARALLAX_PATH")
    if not path:
        _import_error = "SOC_PARALLAX_PATH not set"
        return
    backend = str(Path(path) / "backend")
    if backend not in sys.path:
        sys.path.insert(0, backend)
    try:
        from app.detect import mitre  # noqa: PLC0415
        from app.detect.signals import rules  # noqa: PLC0415
        from app.ingest.parsers.generic import event_from_record  # noqa: PLC0415
        _rules_mod, _mitre_mod, _event_from_record = rules, mitre, event_from_record
    except ImportError as e:
        _import_error = f"import failed: {e}"


def is_available() -> bool:
    _try_import()
    return _rules_mod is not None


def evaluate(technique_id: str, fields: dict) -> dict:
    """Same result shape as sigma_adapter.evaluate() for a uniform report."""
    _try_import()
    if _rules_mod is None:
        return {"available": False, "detected": False, "matched_rule": None,
                "matched_tag": None, "error": _import_error}
    ev = _event_from_record(fields)
    hits = _rules_mod.evaluate(ev)
    if not hits:
        return {"available": True, "detected": False, "matched_rule": None,
               "matched_tag": None, "error": None}
    for hit in hits:
        refs = _mitre_mod.techniques_for(hit.name)
        if any(ref.technique_id == technique_id for ref in refs):
            return {"available": True, "detected": True, "matched_rule": hit.name,
                   "matched_tag": technique_id, "error": None}
    # a rule fired, but none of its declared techniques match the one we're testing
    return {"available": True, "detected": False, "matched_rule": hits[0].name,
           "matched_tag": None, "error": None}
