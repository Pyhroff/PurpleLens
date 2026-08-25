# Vendored rules — provenance

These 3 rules are unmodified copies from the real, official
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) project (fetched at the
commit current as of this project's creation), licensed under the
Detection Rule License 1.1 — see `LICENSE-sigma-rules.txt`. They are not
this project's own detection engineering; they're real-world fixtures used
to test PurpleLens's Sigma-matching engine against actual, production Sigma
syntax rather than hand-simplified examples.

| File | Technique tested |
|---|---|
| `proc_creation_win_powershell_base64_encoded_cmd.yml` | T1059.001 |
| `proc_creation_win_rundll32_no_params.yml` | T1202 |
| `proc_creation_win_schtasks_creation.yml` | T1053(.005) |

Only 3 rules are vendored deliberately — PurpleLens does not claim to
evaluate against the full SigmaHQ corpus (thousands of rules). Growing
Sigma coverage means vendoring one more real rule + verifying it against a
synthetic event, the same way these three were built and tested.
