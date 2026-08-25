# PurpleLens

![tests](https://github.com/Pyhroff/PurpleLens/actions/workflows/tests.yml/badge.svg)

Synthetic-event-driven detection-coverage validation: craft a realistic
telemetry event for a MITRE ATT&CK technique, run it through real detection
rules — a live [soc-parallax](https://github.com/Pyhroff/soc-parallax)
checkout and/or real, vendored [SigmaHQ](https://github.com/SigmaHQ/sigma)
rules — and render the result as an actual, loadable
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer.

Not a demo pipeline with pretend rules: the Sigma side runs unmodified
production rules from the real Sigma project through a from-scratch
condition/modifier evaluator built on top of [pySigma](https://github.com/SigmaHQ/pySigma)'s
parser, and the soc-parallax side imports and runs that project's actual
`rules.evaluate()` + `mitre.techniques_for()` — same code its own test
suite verifies, not a copy that can drift.

## What it actually covers — stated precisely, not oversold

**10 techniques**, not the ~600+ in the full ATT&CK matrix. Each is
annotated with exactly which backend(s) have real rule coverage checked
against it in this project — see `SIGMA_TESTED` / `SOC_PARALLAX_TESTED` in
[`purplelens/techniques.py`](purplelens/techniques.py). "Not tested" and
"tested, not detected" are reported as genuinely different things
(`available` vs `detected` in every result) — a missing rule and a rule
that fired-but-missed are not the same finding, and this tool never
conflates them.

## A real finding this surfaced

`T1202` (rundll32 launched with no arguments — a Cobalt Strike beacon
pattern) is detected by the vendored Sigma rule but **missed** by
soc-parallax — not because nothing fired, but because soc-parallax's
`rule:lolbin_execution` *did* fire (rundll32.exe is in its LOLBin list) —
it's just attributed to T1218 (LOLBin execution generally), a less
specific technique than the no-arguments stealth pattern Sigma's rule
targets. That's a genuine detection-granularity gap between the two
systems, found by actually running the comparison, not asserted from
reading the code.

## Setup

```bash
pip install -r requirements.txt
python -m purplelens.cli                    # Sigma backend only
```

To also enable the soc-parallax backend (optional — point it at a local
checkout, nothing is vendored or duplicated):

```bash
export SOC_PARALLAX_PATH=/path/to/soc-parallax   # the folder containing backend/
python -m purplelens.cli --out layer.json
```

Then open [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)
→ Open Existing Layer → Upload `layer.json`.

## Architecture

```
purplelens/
├── schemas.py              SyntheticEvent — Sigma/Sysmon-native field names
├── techniques.py           curated technique -> synthetic event library
├── sigma_matcher.py        pySigma-parsed rule -> match/no-match evaluator
│                           (condition grammar: and/or/not, parens, "N of x*")
├── sigma_adapter.py        loads sigma_rules/, tags -> technique lookup
├── soc_parallax_adapter.py optional, path-configurable — imports the real
│                           soc-parallax modules if SOC_PARALLAX_PATH is set,
│                           degrades gracefully (not an error) if not
├── navigator.py            coverage results -> real ATT&CK Navigator v4.5 layer
└── cli.py                  ties it together, prints a summary, writes the layer
```

## Why a from-scratch Sigma evaluator, not just pySigma

pySigma's job is parsing Sigma YAML and *converting* rules into backend
query languages (Elasticsearch DSL, Splunk SPL, ...) for a real SIEM to
run — it doesn't ship a "does this rule match this in-memory event"
evaluator. `sigma_matcher.py` is that evaluator, built directly on
pySigma's already-parsed, already-validated rule tree: `contains` /
`startswith` / `endswith` / plain wildcard-aware equality, and the
`and`/`or`/`not`/`(...)`/`N of pattern`/`all of pattern` condition
grammar. Deliberately bounded — an unsupported modifier (e.g. `|re`,
`|base64`) raises `NotImplementedError` naming the modifier, rather than
silently evaluating a rule wrong.

## Vendored Sigma rules

Only 3, deliberately — real, unmodified copies from SigmaHQ/sigma (DRL 1.1
licensed, see `sigma_rules/LICENSE-sigma-rules.txt` and `SOURCE.md`), used
as fixtures to prove the matching engine against actual production syntax,
not hand-simplified examples. This is not a claim of full Sigma-corpus
coverage (thousands of rules exist) — growing it means vendoring one more
real rule + one more hand-crafted synthetic event, the same way these
three were built.

## Tests

```bash
pytest tests/ -v
```

22 tests. Sigma-backend tests run fully offline (vendored rules only) —
a fresh clone with no `SOC_PARALLAX_PATH` set still passes cleanly, 13
tests running and 9 soc-parallax-integration tests skipping gracefully
(not failing) with a clear reason. Set `SOC_PARALLAX_PATH` locally to also
run the live integration checks against a real checkout.

## Origin

Grew out of a detection-coverage regression suite built directly inside
[soc-parallax](https://github.com/Pyhroff/soc-parallax) — 29 tests proving
its own `mitre.yaml`'s claimed rule→technique mapping actually holds. This
project generalizes that same synthetic-event methodology into a
standalone, multi-backend tool with a real Sigma corpus and a visual
ATT&CK Navigator output, rather than staying locked to one system.
