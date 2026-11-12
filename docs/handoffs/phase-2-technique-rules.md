# Handoff: the Phase 2 technique rules (tagger layer 1)

A prompt for the tool that writes the offensive content. The tagger's rule engine, worker and
scoring are built and tested ([phase 2 spec](../05-phase-2-spec.md), 2.4); this adds the rules
it applies. The rules recognise attack techniques from command patterns, which a safety
classifier refuses to let this assistant draft — the same reason the catalogue was handed off.

Produce **`intel/rules/*.yaml`** (add files beside `00-discovery.yaml`, which is the benign
starter and the format reference). Validate with `uv run python -m mirage_intel.tagger lint`
(it compiles every rule) and, once a labelled dataset exists, with
`uv run python -m mirage_intel.tagger score --split dev` (precision and abstention by source).

## Format

```yaml
rules:
  - id: <kebab-case, unique across all files>
    technique: T1059.004        # ATT&CK v20.1
    tactic: TA0002
    protocol: ssh | http | redis | mysql | any
    confidence: 0.9             # 0..1
    any_of: ['<regex>', '<regex>']   # fires if ANY matches (case-insensitive)
    all_of: ['<regex>']              # and every one of these must match
session_rules:                  # fire on the structural session summary, not on text
  - id: <kebab-case>
    technique: T1110.001
    tactic: TA0006
    confidence: 0.9
    when: {failed_before_success: {">=": 3}, auth_success: {">=": 1}}
```

- A rule needs `any_of` or `all_of` (or both). Regexes match the input as the decoy logged it
  (for HTTP, `"METHOD /path"`; for Redis, the space-joined argv; for MySQL, the SQL).
- `session_rules` `when` keys are session-summary fields (`inputs`, `auth_attempts`,
  `auth_success`, `failed_before_success`, `fallbacks`, `duration_s`) with `>=`, `<=`, `==`.

## What to cover

One rule set per tactic the catalogue uses, matching the catalogue's own procedures so the
tagger can recover their techniques: Execution, Persistence, Privilege Escalation, Defense
Evasion / Stealth / Defense Impairment, Credential Access, Discovery (extend the starter),
Lateral Movement, Collection, Command and Control, Impact. Aim for the frequent, unambiguous
patterns; prefer abstaining (no rule) over a wrong technique. Keep each rule tight enough that
it does not fire on an unrelated command.

## Rules

- Every `technique`/`tactic` is ATT&CK v20.1 and matches how the catalogue labelled the same
  procedure (so scoring measures recognition, not disagreement about labels).
- No marker words or literal addresses in the regexes beyond what a real command contains.
- Do not touch the engine, the worker, `eval/split.yaml`, or any other file.
