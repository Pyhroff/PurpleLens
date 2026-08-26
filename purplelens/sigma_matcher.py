"""Evaluate a real, pySigma-parsed SigmaRule against a synthetic event.

pySigma's own job is parsing Sigma YAML into structured objects and
converting rules into backend query languages (Elasticsearch DSL, Splunk
SPL, ...) for a real SIEM to execute. It doesn't ship a "does this rule
match this in-memory event" evaluator — that's what this module is: a
direct evaluator over pySigma's already-parsed, already-validated
SigmaDetection/SigmaDetectionItem tree, so PurpleLens can test rules
without needing a real SIEM behind them.

Scope, stated plainly: supports the modifiers and condition grammar that
actually appear in this project's vendored fixture rules — plain
(wildcard-aware) equality, contains, startswith, endswith; and/or/not,
parentheses, "N of <pattern>", "all of <pattern>". Sigma's full spec is
larger (regex, base64, field-to-field comparisons, near/temporal
correlations, ...) — unsupported modifiers raise NotImplementedError with
the modifier name rather than silently evaluating wrong, so a rule using
something outside this list fails loudly, not quietly-incorrectly.
"""
from __future__ import annotations

import fnmatch
import re

from sigma.conditions import ConditionAND
from sigma.modifiers import (
    SigmaAllModifier,
    SigmaContainsModifier,
    SigmaEndswithModifier,
    SigmaStartswithModifier,
)
from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.types import SigmaString, SpecialChars

# Per-value comparison modifiers _value_matches() actually implements.
_SUPPORTED_MODIFIERS = (SigmaContainsModifier, SigmaEndswithModifier, SigmaStartswithModifier)
# Modifiers that affect how the value LIST combines (AND vs OR), not how a
# single value compares — already fully handled by item.value_linking in
# _match_item(), so they're not "unsupported," just not this function's job.
_VALUE_LINKING_MODIFIERS = (SigmaAllModifier,)


def _sigma_string_to_pattern(s: SigmaString) -> str:
    """SigmaString's parts are plain string fragments interleaved with
    SpecialChars (WILDCARD_MULTI='*', WILDCARD_SINGLE='?') — rebuild into
    an fnmatch-style pattern string."""
    out = []
    for part in s.s:
        if part is SpecialChars.WILDCARD_MULTI:
            out.append("*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            out.append("?")
        else:
            out.append(str(part))
    return "".join(out)


def _value_matches(value, actual: str, modifiers: list) -> bool:
    """One SigmaString value against the actual field string, honoring
    whichever of the supported modifiers is present (case-insensitive,
    matching Sigma's own default matching semantics)."""
    unsupported = [m for m in modifiers
                  if m not in _SUPPORTED_MODIFIERS and m not in _VALUE_LINKING_MODIFIERS]
    if unsupported:
        names = [m.__name__ for m in unsupported]
        raise NotImplementedError(f"unsupported Sigma modifier(s): {names}")

    actual_l = (actual or "").lower()
    if isinstance(value, SigmaString):
        pattern = _sigma_string_to_pattern(value).lower()
    else:
        pattern = str(value).lower()

    if SigmaContainsModifier in modifiers:
        return fnmatch.fnmatchcase(actual_l, f"*{pattern}*")
    if SigmaEndswithModifier in modifiers:
        return fnmatch.fnmatchcase(actual_l, f"*{pattern}")
    if SigmaStartswithModifier in modifiers:
        return fnmatch.fnmatchcase(actual_l, f"{pattern}*")
    return fnmatch.fnmatchcase(actual_l, pattern)  # plain (possibly wildcarded) equality


def _match_item(item: SigmaDetectionItem, fields: dict) -> bool:
    if item.field is None:
        raise NotImplementedError("keyword (fieldless) detection items are not supported")
    actual = fields.get(item.field)
    if actual is None:
        result = False
    else:
        actual_str = str(actual)
        results = [_value_matches(v, actual_str, item.modifiers) for v in item.value]
        combined = all(results) if item.value_linking is ConditionAND else any(results)
        result = combined
    return (not result) if item.negated else result


def match_detection(node, fields: dict) -> bool:
    """Recursively evaluate a SigmaDetection (which may nest further
    SigmaDetections) or a leaf SigmaDetectionItem against event fields."""
    if isinstance(node, SigmaDetectionItem):
        return _match_item(node, fields)
    assert isinstance(node, SigmaDetection)
    results = [match_detection(child, fields) for child in node.detection_items]
    return all(results) if node.item_linking is ConditionAND else any(results)


def _tokenize(condition: str) -> list[str]:
    return re.findall(r"\(|\)|[A-Za-z0-9_*]+", condition)


class _ConditionParser:
    """Recursive-descent evaluator for Sigma's condition grammar:
    or > and > not > atom, where atom is '(' expr ')', 'N of pattern',
    'all of pattern', or a bare selection name. `selections` maps every
    named detection to its already-computed match_detection() result."""

    def __init__(self, tokens: list[str], selections: dict[str, bool]):
        self.tokens = tokens
        self.pos = 0
        self.selections = selections

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _eat(self, expected: str | None = None) -> str:
        tok = self.tokens[self.pos]
        if expected and tok.lower() != expected:
            raise ValueError(f"condition parse error: expected '{expected}', got '{tok}'")
        self.pos += 1
        return tok

    def parse(self) -> bool:
        return self._or()

    def _or(self) -> bool:
        left = self._and()
        while self._peek() and self._peek().lower() == "or":
            self._eat()
            right = self._and()
            left = left or right
        return left

    def _and(self) -> bool:
        left = self._not()
        while self._peek() and self._peek().lower() == "and":
            self._eat()
            right = self._not()
            left = left and right
        return left

    def _not(self) -> bool:
        if self._peek() and self._peek().lower() == "not":
            self._eat()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        if self._peek() == "(":
            self._eat("(")
            val = self._or()
            self._eat(")")
            return val
        if self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1].lower() == "of":
            quant = self._eat()
            self._eat("of")
            pattern = self._eat()
            matched_names = [n for n in self.selections if fnmatch.fnmatchcase(n, pattern)]
            values = [self.selections[n] for n in matched_names]
            if quant.lower() == "all":
                return bool(values) and all(values)
            return sum(1 for v in values if v) >= int(quant)
        name = self._eat()
        return self.selections.get(name, False)


def rule_matches(rule, fields: dict) -> bool:
    """Does this parsed SigmaRule fire against this synthetic event's fields?"""
    selections = {name: match_detection(det, fields)
                 for name, det in rule.detection.detections.items()}
    condition = rule.detection.condition[0]
    return _ConditionParser(_tokenize(condition), selections).parse()
