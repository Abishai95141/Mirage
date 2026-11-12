# Handoff: the Phase 2 attack catalogue and demo scenarios

This is a prompt for the model that writes the offensive content. It defines the file formats,
the rules the content must follow, and the techniques to cover — not the commands themselves.
The runner, the label join and the drivers are already built and tested ([phase 2
spec](../05-phase-2-spec.md)); this adds only the procedures and scenarios they run.

Validate everything you write with `uv run mirage-lab lint lab/scenarios` before finishing; it
must report zero problems. Nothing here runs anything — the runner only drives the project's
own emulated decoys on an isolated lab network.

## What to produce

1. **`lab/catalogue/*.yaml`** — at least 160 procedures over at least 40 ATT&CK techniques
   (v20.1), each technique with at least four procedures, from three sources in roughly equal
   parts (`own`, `atomic`, `corpus`). The 19 starter procedures already in `lab/catalogue/`
   stay; add files alongside them (e.g. `10-discovery.yaml`, `20-persistence.yaml`).
2. **`lab/scenarios/**/*.yaml`** — scenarios that string procedures into realistic sessions.
3. **`lab/scenarios/demo/demo-1-*.yaml` and `demo-2-*.yaml`** — the two demos (below), which
   run live in CI and must produce the exact labels the assertions check.

Do **not** assign the train/dev/test split or edit `eval/split.yaml`; that is frozen
separately after this content exists, so that no rule is written against the test set.

## Catalogue format

```yaml
attack_version: "20.1"          # every file names the same version
procedures:
  - id: <kebab-case, 4-64 chars, unique across all files>
    technique: T1059.004        # omit both technique and tactic for a step that is no
    tactic: TA0002              #   technique (e.g. `cd`); never one without the other
    source: own | atomic | corpus
    protocol: ssh | http | redis | mysql
    kind: input | upload | auth # default input
    template: "<the input, with {{slots}}>"   # omit for kind: auth
    ref: "<optional: Atomic test GUID, or corpus note>"
```

- **`template`** is the exact input sent. For `ssh` it is a shell command line. For `http` it
  is `METHOD /path[?query]` with an optional form body after a space
  (`POST /wp-login.php log=admin&pwd=x`). For `redis` it is a command line (`SET {{word}} 1`).
  For `mysql` it is one SQL statement.
- **`kind: upload`** is SSH only; its `template` is the destination path (random bytes are
  sent). **`kind: auth`** is SSH or MySQL only and carries no template (the login is driven by
  the scenario's `login:` block).
- **Slots** are filled per run from inert generators; use only these names (a trailing digit
  makes a distinct value: `file2`): `ip host domain url file dir path hex port user num word`.
  Every host or URL slot resolves to a documentation range or `.example/.test/.invalid` name,
  so a command can never name a real machine. Put every variable part in a slot — never a
  literal address, domain or random string.

### Hard rules the lint enforces (a violation blocks the whole run)

- An input is **one line**, stripped, no newlines.
- An input must not contain an **ATT&CK ID** (`T1059`, `TA0002`), a procedure or scenario
  **ID**, or any **marker word**: `mirage atomic scenario selftest honeypot cowrie gate1`.
  So name procedures and scenarios without words that could appear in a command.
- A scenario uses procedures from **one split only** (checked later, but keep each scenario's
  procedures thematically narrow so the split can keep them together).

### Content safety (these make the content inert, not realistic malware)

- No real malware, exploit payloads that work, wallet addresses, pool URLs, or C2 hosts. A
  "downloaded miner" is random bytes to a documentation URL; a "reverse shell" connects to a
  documentation IP that nothing answers. The decoys are emulators and run none of it.
- Sources: `own` = written for this project; `atomic` = an Atomic Red Team test's `sh`/`bash`
  command, with its GUID in `ref`, slots substituted for its inputargs; `corpus` = a frequent
  command template from the Zenodo seed sample (`data/seed/`). Keep the three in balance.
- Many commands will answer "command not found" — that is fine; the label is on the input.

## Scenario format

```yaml
id: <kebab-case>
actor: {class: scanner | scripted_bot | human | llm_agent, timing: scan | bot-fast | bot-slow | human, patience: 2}
sessions:
  - protocol: ssh
    channel: shell | exec            # ssh only
    login: {user: root, guesses: 6, procedure: <an auth procedure>}
    gap_s: 0                         # pause before this session
    steps:
      - id: s1
        procedure: <a catalogue id>
        with: {dir: /etc}            # pin a slot (optional)
        expect: "regex"              # on the output (optional)
        expect_status: 0             # exec channel only
        on_fail: continue | retry | leave | {goto: s4}
        retries: 2
```

A step reacts to the decoy with `expect`/`expect_status` and `on_fail`, so the session can
retry another way, skip ahead or leave — that is what gives a learning policy something to
learn. `llm_agent` is in the class list but no agent scenarios are needed yet (phase 4).

## The two demos (run live in CI — the labels must come out exactly)

**`demo-1` — SSH brute force to a miner.** A `scripted_bot` guesses SSH passwords and gets in;
runs discovery (`uname -a`, `w`, `crontab -l`); tries to download a miner and, when that fails
for lack of egress, uploads it (`kind: upload`); runs it with pool-style arguments; adds a
cron persistence entry. The procedures must carry these techniques so the session's labels
are exactly: Credential Access, Discovery, Command and Control, Execution, Persistence,
Impact. Keep the miner upload a distinct `kind: upload` step (CI checks it became an indexed
artifact).

**`demo-2` — web credential theft, reused on MySQL.** From one address, a `scanner` sweeps web
paths and does a `GET /.env`, which the decoy serves with the planted database credential.
From a second address (a second session in the same scenario, different source), a
`scripted_bot` logs in to MySQL with `login: {user: <the planted user>}` and reads the customer
table. CI checks: the first session is `scanner` with Reconnaissance and Credential Access;
the second is `scripted_bot`; a `token.triggered` fires; both sessions share one actor by the
honeytoken link, with the second address recorded. The planted user and password are in
`build/profile/mysql.json` and `build/profile/tokens.json` — reference the user by name in the
scenario; the runner looks the password up, so it never appears in the scenario file.

## When done

`uv run mirage-lab lint lab/scenarios` is clean, then the owner runs `make up && make lab-up &&
make lab-run SCENARIOS=/lab/scenarios` and checks `SELECT * FROM mirage.sim_runs FINAL`: every
run must show `no_event = 0` and `mismatch = 0`. A step that logs `no_event` means the decoy
did not capture what the scenario sent — usually a command the emulator answers differently
than expected; adjust the `expect`, not the join.
