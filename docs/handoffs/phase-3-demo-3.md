# Handoff: demo 3 (phase 3)

This is a prompt for the model that writes the offensive content, as
[the phase 2 catalogue brief](phase-2-catalogue.md) and
[the depth brief](phase-3-depth-scenarios.md) were. It defines the two scenarios of demo 3,
where their files go and the rules the content must follow. It does not contain the commands.

Read both earlier briefs first. The catalogue and scenario formats, the lint's hard rules and
the content-safety rules are unchanged, and everything in them still applies except where this
brief says otherwise. Validate with `uv run mirage-lab lint lab/scenarios`; it must report zero
problems.

## What demo 3 is

One intruder, working by hand, in two parts ([phase 3 spec, 3.8](../06-phase-3-spec.md)):

- **3a** runs on a laptop and in CI on every change. The intruder guesses root's SSH password,
  looks the host over, saves a note to a file, looks for credentials, finds one, and later
  uses it on the database from a second address.
- **3b** runs on the Linux host only. The same intruder gets as far as a hands-on survey, the
  policy moves the session into a real throwaway container, and the intruder writes a small
  script there and runs it.

A depth scenario is a measurement: it may end early, and how far it gets is the result. A demo
is an assertion: it must reach its last step on every run, and CI fails when it does not. That
changes two things about how you write it. Every line must be one the decoy is known to
answer, and the lines must be the same text on every run.

## One difference from the depth brief

The depth brief told you nothing about what the decoy has prepared, so that a check could not
be written to agree with it. Here you are told **which commands** have a prepared answer,
because the demo's first part has to use them. You are still not told **what the answers
are**, and the rule behind that has not moved:

- Write every check from what a real Debian 12 host prints.
- Do not open `decoys/profiles/rendered/`, `decoys/profiles/hardware/`, `eval/recordings/` or
  anything under `responder/`, and do not ask for their contents.

## What to produce

1. **`lab/catalogue/98-demo-intruder.yaml`**: every procedure the two scenarios use, their
   login procedures included. IDs begin with `h-`.
2. **`lab/scenarios/demo/demo-3a-<name>.yaml`**
3. **`lab/scenarios/demo/demo-3b-<name>.yaml`**

Rules for the files:

- **A set of its own.** The phase 2 catalogue and the depth catalogue are both frozen, so demo
  3's procedures are a third set, recognised by the file name above. A scenario may not mix
  sets, and the lint refuses one that does. That includes the login: write new `auth`
  procedures for SSH and for MySQL in this file.
- **Do not reuse or adapt a depth procedure.** Half of them are held out, and you are not
  told which. `uv run python -m eval.split check` lists every demo procedure that is
  near-identical to a held-out one, by ID. An ordinary command may appear in that list. A
  procedure built from a depth one may not.
- **No split.** Do not edit `eval/split.yaml` or `eval/split-depth.yaml`. Demo procedures are
  in neither, on purpose, and the lint accepts that for this set only.
- **The scenarios may share procedures with each other.** 3b's login and survey can be 3a's.

## The intruder

A person at a keyboard, in both scenarios:

```yaml
actor: {class: human, timing: human, patience: 1}
sessions:
  - protocol: ssh
    channel: shell
    login: {user: root, guesses: 4, procedure: <the SSH auth procedure of this file>}
```

Three to six wrong guesses, then the right password. The runner supplies it.

## The rule that shapes every line

Under the policy the demo runs with, each command is answered by one of three things:

1. **The emulator**, for a command Cowrie v3.1.6 has a module for (upstream,
   `src/cowrie/commands/`).
2. **A prepared answer**, for exactly these seven, each alone on its line and spelled exactly
   so: `lscpu`, `nproc`, `df -h`, `ss -tln`, `nginx -v`, `nginx -t`, `sshd -t`. Another flag,
   another flag order or an added argument is a different command and has no prepared answer.
3. **The model**, for any command the first two do not have.

In CI the model is a set of recordings, and exactly two will exist: the two steps of 3a named
below. An unknown command anywhere else has no recording, and the demo fails. So, apart from
those two steps:

- **Every line is one command, and it is from list 1 or list 2.**
- **One simple command to a line.** No pipe, no `;`, `&&` or `||`, no command substitution,
  no redirection, no background job, no glob. Each of those is either several commands to the
  decoy or shell behaviour the emulator does not have.

Choose commands by what exists. Check them by what a real host prints.

## Part 3a

Two sessions in one scenario.

### Session 1: SSH, as root

Fourteen to twenty steps, in this order.

**1. The survey.** A person's first look at a host they have just entered.

- At least five of the seven prepared commands, with at least two from `lscpu`, `nproc`,
  `df -h` and at least two from `ss -tln`, `nginx -v`, `nginx -t`, `sshd -t`.
- Three to five emulated commands among them, as a person would mix them.
- Every step is a gate with `on_fail: leave`. Check the shape of the answer: a header and
  its columns, `key: value` lines, a number alone on a line.
- A command that prints nothing when all is well is checked by a pattern that holds when no
  error is printed.
- The decoy claims one of three machine shapes, chosen per installation. Expect no particular
  count, size or model name.

**2. The model step.** One command that neither list has. It is the one answer in the demo
that only the model can give, so choose it with care:

- It only reports. It changes nothing, asks nothing, opens no connection and does not wait.
- Its true answer depends on what the host's files say about accounts, installed packages or
  service configuration, so that no fixed text could answer it for every installation.
- Its answer does not name the caller's own connection, a process ID or the time.
- On a real host it prints at most twenty lines.
- Any argument names something every installation has: root, a package of the reference
  image, a path every Debian 12 host has. Host names, the other users and addresses differ
  per installation and are not known to you.
- It is a gate with `on_fail: leave`, checked for shape as the survey is.

**3. The note.** Three steps that test whether a change made through the model is still there
for the emulator:

- A command the emulator lacks creates a file. The command names the file as an argument and
  creates it itself; a redirection would be the shell's work, not the command's. The line
  carries the text that ends up in the file.
- An emulated listing shows the file. Gate on its name.
- An emulated read prints it. Gate on a word of the text the first step carried.

The file goes in a directory every host has and root may write to.

**4. The credential.** Three steps:

- *The search.* A first credential-seeking input, labelled with a Credential Access
  technique. The policy answers it by planting a file, so two things must be true of the
  session up to and including this step: nothing has listed root's home directory, and this
  step does not look there either. It also must not print the web application's own
  configuration files under `/var/www/html`, which hold a different planted credential.
- *The find.* An emulated listing of root's home directory, hidden files included. Gate on
  the name `.my.cnf`, with `on_fail: leave`.
- *The read.* An emulated read of `/root/.my.cnf`, with a `capture` that takes the value of
  its `password` line: the key at the start of a line, optional spaces around `=`, the value
  to the end of the line, and a carriage return tolerated, as demo 2's capture does.

The file is a MariaDB client option file, in that format, for the account `dbbackup`.

### Session 2: MySQL, from a second address

```yaml
  - protocol: mysql
    source: 2
    actor: {class: scripted_bot, timing: bot-fast}
    gap_s: 2
    login: {user: dbbackup, procedure: <the MySQL auth procedure of this file>, password_from: <the capture>}
```

Two steps, as demo 2's second session has: one statement that shows which account the session
runs as, gated on the account's name, and one that reads the customer table, gated on `@`.
Write new procedures for both.

### Labels

CI derives the demo's expected tactics from your labels when the scenario is loaded, so a
wrong label is a wrong assertion.

- Label each step with the technique it is, from ATT&CK v20.1, and the tactic that technique
  belongs to.
- Session 1 must carry the guessed login, Discovery, and two different Credential Access
  techniques (the search and the read). Session 2 must carry the use of a valid account and
  Collection.
- A step that is no technique carries none. Do not put a technique on the note's three steps
  unless what the intruder does there is one.

## Part 3b

One SSH session, same actor and login. It runs on the Linux host only.

At some input after the second, the policy hands the session to a real Debian container built
from the reference image, with the session's files carried over. From then on every line
really runs, as root. That container has no route out: an outbound connection is answered by
a sinkhole that records where it was going and sends nothing on. You cannot know at which
input the handover happens, so the scenario is written to hold either way.

In this order:

1. **A file, within the first two inputs.** An emulated command creates a small file at a
   fixed path. The policy never hands over before the third input, so this file exists before
   the handover whenever it comes.
2. **A survey of at least five inputs,** under 3a's rule: each line from list 1 or list 2.
3. **The file from step 1, read back.** An emulated command; gate on its content.
4. **The script.** The session writes a short script onto the host with its own input lines,
   makes it executable and runs it. An `upload` procedure cannot do this: it sends random
   bytes, which do not run. From here on a line may use the shell freely, still one line to a
   step. The script does two things and no more:
   - it writes one file at a fixed path, holding a fixed word;
   - it tries one outbound TCP connection to an `{{ip}}` and `{{port}}` slot, with a timeout
     of a few seconds.
5. **The script's file, read back.** Gate on the word.

Rules for 3b:

- **No step gates on whether the connection succeeded.** In the container the sinkhole
  answers it. On the reference host, where the owner checks the scenario, it fails.
- **The script uses only what the reference image has** (the depth brief lists it). If it
  needs anything else, name the tool in a comment at the top of the scenario and do not work
  around it.
- **The depth brief's safety rules for inputs that really run apply to every line,** and the
  lint enforces them for this set.
- The script leaves nothing behind but its one file. It changes no account, credential or
  service and sets up nothing that runs later.

## Fixed text

Recordings are keyed on the whole request: the command, and what the session has done before
it. So in 3a's first session:

- **Pin every slot** with `with:`, in every step. A slot left free renders differently on
  each run.
- **No `cd` and no change to the environment** before the model step and the note.
- Once delivered, the model step, the note's first step and every step before them are
  frozen. A later edit to any of them means recording again.

In 3b, pin the two paths. The address and port slots stay free.

## Rules for the checks

- **Every check holds on a stock Debian 12 host,** with one exception: the find, the read and
  session 2 of 3a depend on a file the policy plants, which a plain host does not have.
- **Structure, not exact text.** No version numbers beyond what Debian 12 fixes, no dates,
  sizes, addresses or host names.
- **Not from the decoy's behaviour,** in either direction, as in the depth brief.

## When done

`uv run mirage-lab lint lab/scenarios` is clean, and `uv run python -m eval.split check`
reports the demo procedures with no problem.

The owner then does three things and returns one list:

1. Runs 3a's first session up to the search, and all of 3b, against the reference container.
2. Runs both against the decoy.
3. Returns the steps whose checks failed on the real host, and the lines the decoy answered
   from neither list. Each is named by its step ID, with what the host or the decoy printed.

Fix those, and only those. After that the two recordings are made and the text freezes.

## Not yours

These are built around the scenarios by the owner. Do not write, stub or work around them:

- the planted file, its account and where the policy puts it;
- the two recordings;
- the handover to the container, and the sinkhole;
- the assertions CI makes on the result.
