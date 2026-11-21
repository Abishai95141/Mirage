# Showing MIRAGE to people: the public showcase

15 November 2026 · the services are in [`compose/docker-compose.yml`](../compose/docker-compose.yml) under the profile `showcase`

The showcase is a link that anyone can open in a browser to see the dashboards live, while a lab host does the work. With a password as well, the same link gives a terminal into the SSH decoy, so someone can attack it and watch the system respond. It is the one deliberate way anything in this project is reachable from the internet, so this page says exactly what it opens and what it does not.

## What a visitor gets

**Anyone with the link:** the nine Grafana dashboards, read-only and live: sessions, technique labels, predicted actor classes, alerts, honeytokens, artifacts, the policy's decisions and the lab page. If someone runs a scenario on the host or types in the console while people are watching, the dashboards show it as it happens.

**Anyone with the link and the console's password:** a terminal at `<link>/console/` (user `presenter`). It opens a root shell on the SSH decoy. The visitor types what they like; the decoy answers; the session is recorded, classified and tagged like any other, and appears on the dashboards within seconds, marked as a real person's.

## How the console works, and why the decoy is still not on the internet

The console is the lab's own human recorder (`make lab-human`) with a browser in front of it. The visitor's keys go from the browser to a terminal server ([ttyd](https://github.com/tsl0922/ttyd) 1.7.7, pinned by hash), whose only program is the recorder. The recorder opens an SSH session to the decoy through the lab edge, from a simulated address in the lab's capture range, exactly as a lab run does.

So nothing connects to the decoy from the internet. No SSH port is published, the decoy never sees a real address, and a person without the password reaches only the proxy, which answers them itself. The exposure checklist in the build plan still governs putting a decoy on the internet; this does not do that.

| | |
| --- | --- |
| Who can type | Only someone who has the password. The proxy checks it before a request reaches the terminal server, and the terminal server refuses any request that does not carry it, wherever it comes from. A browser that has signed in is handed a ticket (a cookie that scripts cannot read and other sites cannot use) to show in place of the password, because some browsers do not send a password on the terminal's own connection. A ticket works until the password is replaced |
| What they can reach | The SSH decoy's shell, and nothing else. The console's container sits on the lab network and on an internal network shared with the proxy and the showcase's Grafana. Neither has a route out, and neither has an address on the lab machine, so the container cannot reach the machine's own services either; the recorder checks the routes before every session, and `make showcase-check` probes all of it from inside |
| How long | A session ends after 15 minutes, when the visitor exits the shell, or when they close the tab. Three people at once; 300 sessions per start of the showcase |
| What is kept | Every session, with what was typed, in the store, under the scenario name `showcase-visitor`. Visitors are told this before the shell opens |
| File transfer | Off. Only keys go in and only the screen comes out |
| Guessing the password | Ten wrong tries a minute from one visitor, then that visitor waits. The password is 32 random characters |

## What it does not open

| | |
| --- | --- |
| The decoys | Not reachable from the internet. The tunnel is on a network of its own with one other member, the proxy |
| The real Grafana | Not reachable. The showcase is a second Grafana; the real one stays on `127.0.0.1` with its login |
| Signing in to the dashboards | Impossible. The showcase's login form and basic auth are off; every visitor is an anonymous viewer. The console's password is not passed on to Grafana |
| Writing to the store | Impossible. The showcase reads as a store user that can only read |
| A port on the machine | None is opened to the network. The tunnel is an outbound connection; the preview port is on `127.0.0.1` |

## What it does open, stated plainly

- **Everything in the `mirage` database can be read while the link is up**, not only what the dashboards show. Grafana runs whatever query a visitor sends, as the read-only user. On a lab host that is lab data: simulated attacks and their commands, the labels, the lab's answer key, the credentials of the public lab seed, and whatever visitors typed in the console. That is why the showcase belongs on a lab host and never on a sensor that has seen real traffic.
- **Someone with the password can use the decoy as an attacker would.** That is the point of it. They cannot leave the decoy, and the decoy has no way out to the internet, but what they type is stored and shown. Give the password only to people you would let do that, and replace it afterwards.
- **Known gap, open on 15 November 2026: the decoy's container can reach the lab machine itself.** The decoy networks are internal, which stops traffic leaving the machine, but the SSH decoy's container can still open a connection to the lab machine's own SSH port at its networks' gateway addresses (measured: both answer). The console's two networks were closed to this the same day (the bridge is given no address on the machine); the decoy networks were not. Whether a console visitor can make the decoy open such a connection was not tested. Close it before giving the password to anyone you would not also let try the lab machine's SSH login, and before any decoy faces the internet.
- **Console sessions are labelled as a real person's.** They are kept under their own scenario name, which has no place in the frozen split, so a dataset export that names one of their runs fails its checks; none gets into a dataset by accident. Keep it that way unless you have looked at them: a visitor is not a consenting study participant, and may have pasted a script.
- **Visitors cost the machine something.** Each query is held to 10 seconds, 200 MB and two threads, and all visitors together to 600 queries and 120 seconds of query time a minute. One visitor is held to 600 requests in ten seconds. A visitor cannot raise those limits.
- **The link is unguessable, not secret.** Anyone who has it can pass it on. It is new every time the showcase starts and dead when it stops.
- **It goes through Cloudflare's account-less tunnel service**, which has no uptime guarantee and is subject to Cloudflare's terms. Cloudflare ends the encryption, so it can see what passes, the console's password included. For a fixed address, use a Cloudflare account and a domain of your own in place of the quick tunnel.

## How to use it

On a lab host, from the repository, with the stack up (`make up`):

```bash
make showcase-preview
```

Starts the showcase on the machine only, at `http://127.0.0.1:3301`, with the console at `/console/`. Look at it first: this is what the public will see.

```bash
make showcase-check
```

Tries the preview as a visitor would and prints what it found: the dashboards answer anyone and take no logins; the console answers nobody without the password and slows someone guessing; a signed-in visitor gets the decoy's shell and the session is recorded, by a closed tab too; and the console's container cannot reach the lab machine. It sends nothing off the machine. Each run leaves two sessions under `showcase-visitor` that the script typed, not a person. Run it before every `make showcase-up`.

```bash
make showcase-password
```

Prints the console's user and password. Nothing else prints it.

```bash
make showcase-up
```

Opens the public link and prints it.

```bash
make lab-run SCENARIOS=/lab/scenarios/demo
```

Runs the two demos, so there is something to watch: a brute-forced SSH login that ends in a miner, and a web credential theft reused on MySQL.

```bash
make showcase-down
```

Closes the link and stops the showcase. It does not come back by itself, not even after a reboot.

```bash
make showcase-password-new
```

Replaces the console's password. Do this after showing it to people; the new one takes effect the next time the showcase starts.

## The order, with phase 3 in it (20 November 2026)

Everything here was run on the lab host after it restarted on 20 November. All commands are
run on the lab host, from the repository (`cd ~/mirage`).

**After a restart of the machine.** The core stack comes back by itself (the decoys, the
policy, the pipeline, the store, Grafana). The model server and the showcase do not, on
purpose: start them in this order.

| # | Command | What it does | Who runs it |
| --- | --- | --- | --- |
| 1 | `make up` | Starts the stack (a few minutes). After a plain restart of the machine it is already up: `make ps` shows it | Anyone |
| 1b | `make tagger-model` | Starts the worker that labels each command with its ATT&CK technique; the dashboards' technique panels are empty without it | Anyone |
| 2 | `make llm-up` | Optional. Starts the model on the GPU, for commands the decoy has no answer of its own for. Without it everything else works, and those commands say "cannot execute binary file" | Anyone |
| 3 | `make showcase-preview` | The showcase on the machine only (`http://127.0.0.1:3301`, console at `/console/`) | Anyone |
| 4 | `make showcase-check` | Tries it as a visitor would; must end with "0 problem(s)" | Anyone |
| 5 | `make showcase-password` | Prints the console's login | You: it prints a secret |
| 6 | `make showcase-up` | Opens the public link and prints it. A new address every time | You: it faces the public |
| 7 | `make lab-run SCENARIOS=/lab/scenarios/demo` | Runs the two demos, so the dashboards move | Anyone |

If step 2 fails with "driver not loaded": the machine restarted into a kernel that has no
NVIDIA module yet. `sudo bash tools/lab-host/gpu-driver.sh` installs it (about 8 MB) and
loads it. This needs your password.

**What to type in the console, to show phase 3.** Each is answered by the decoy itself,
with no model, and each was checked against a real Debian 12 host.

| Type this | What it shows |
| --- | --- |
| `lscpu` then `nproc` | The machine the decoy claims to be: a recorded KVM guest, not Cowrie's fixed text |
| `ps -ef` then `ss -tlnp` | The same services in both, by the same process IDs; `ss` is laid out as the real one |
| `ss -tnp` | The visitor's own connection, held by the `sshd` that `ps` shows for them |
| `getent passwd root caleb` and `tty` | Accounts from the decoy's own files; the terminal the visitor is on |
| `for ((i=1;i<=3;i++)); do echo $i; done` | Bash syntax stock Cowrie cannot read |
| `[[ -d /etc && ! -e /nosuch ]] && echo yes` | The same |
| `install -m 600 /etc/hostname /tmp/f; stat -c '%a %s' /tmp/f` | A file command with its real effect |
| `truncate -s 20 /tmp/f; wc -c /tmp/f; shred -u -v /tmp/f` | The same; `shred` prints what the real one prints |
| `printf abc > /tmp/c; cat /tmp/c \| wc -c` | 3, as on a real host (stock Cowrie says 4) |
| `passwd`, then log out and in with the new password | A change that holds for the visitor who made it |

With the model up (step 2), also: `chage -l root`, `dpkg -s openssh-server`, `lastlog -u
root`. These are the model's answers: plausible, and exactly right about one time in four
([the measurements](experiments/phase-3/llm-bench.md)). Ask the same one twice, or in a second login: the answer is the same.

**Numbers to show on the host**, each a command that prints its own result:

| Command | What it prints | Takes |
| --- | --- | --- |
| `make probe` | The fingerprint suite: the decoy against a real host, check by check. On 20 November: 474 pass, 0 fail, 10 known gaps | 15 min |
| `make probe PROBE_ARGS="--groups consistency"` | Only the checks that the decoy does not contradict itself | 3 min |
| `make llm-status` | Whether the model is up, and the GPU's memory | Seconds |
| `make llm-standings` | Which programs the model has answered, and which are refused | Seconds |
| `make llm-bench` | The model's speed and how often it is right (model up) | 15 min |

**To stop.** `make showcase-down` closes the link and the console. `make llm-down` stops
the model. `make down` stops everything (stack, lab, tagger, model, showcase) and keeps
the data; start again from step 1.

## What to say and what not to say

The showcase shows a working lab. It does not show real attackers: nothing has faced the internet, and apart from console visitors the "person" class is the lab's own typing generator. The results worth quoting, with their limits, are in [the phase 2 spec, section 12](05-phase-2-spec.md).
