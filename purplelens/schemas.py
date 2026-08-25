"""The synthetic event shape PurpleLens generates and evaluates rules against.

Field names deliberately match real Sysmon/Sigma field naming (Image,
CommandLine, ParentImage, User, TargetObject) rather than an abstracted
schema — real Sigma rules are written against these exact field names, so
using anything else would mean silently testing something other than what
the rules actually check.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SyntheticEvent:
    """One synthetic telemetry event representing a technique executing.
    Not a real event from a real endpoint — a hand-crafted, minimal event
    carrying exactly the fields a specific rule's trigger condition needs,
    nothing more. `fields` holds everything in Sigma/Sysmon-native naming
    (Image, CommandLine, ParentImage, User, TargetObject, ...); `event_type`
    is used by the soc-parallax adapter, which classifies by a separate,
    generic event_type string rather than logsource category."""
    technique_id: str
    description: str
    fields: dict = field(default_factory=dict)
    # generic-parser hint: process | registry_set | network | dns | logon
    event_type: str = "process"
