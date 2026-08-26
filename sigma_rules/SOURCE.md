# Vendored rules — provenance

5 rules, unmodified copies from the real, official
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) project, licensed under
the Detection Rule License 1.1 — see `LICENSE-sigma-rules.txt`. They are
not this project's own detection engineering; they're real-world fixtures
used to test PurpleLens's Sigma-matching engine against actual, production
Sigma syntax rather than hand-simplified examples.

One disclosed exception: `registry_set_susp_run_key_img_folder.yml` had a
missing opening quote in one list entry in the upstream file (`- :\ProgramData'`,
an unmatched trailing quote with no matching open) that broke YAML parsing
outright — fixed to `':\ProgramData'` so the rule loads at all. Everything
else in that file, and all content in the other 4 files, is byte-for-byte
as fetched.

| File | Technique tested | Notable feature exercised |
|---|---|---|
| `proc_creation_win_powershell_base64_encoded_cmd.yml` | T1059.001 | basic contains/endswith, and/or/not condition |
| `proc_creation_win_rundll32_no_params.yml` | T1202 | simple selection + exclusion filter |
| `proc_creation_win_schtasks_creation.yml` | T1053(.005) | "not 1 of filter_*" quantifier |
| `proc_creation_win_susp_lsass_dmp_cli_keywords.yml` | T1003(.001) | `contains\|all` (AND-combined value list) |
| `registry_set_susp_run_key_img_folder.yml` | T1547(.001) | nested parens, "all of pattern\*", multiple exclusion filters |

Only 5 rules are vendored deliberately — PurpleLens does not claim to
evaluate against the full SigmaHQ corpus (thousands of rules). Growing
Sigma coverage means vendoring one more real rule + verifying it against a
synthetic event, the same way these five were built and tested — and, per
the two rules above, sometimes finding a new Sigma modifier/grammar
feature to actually implement along the way, not just a new YAML file to
drop in.
