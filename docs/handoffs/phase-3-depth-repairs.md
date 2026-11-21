# Handoff: six depth procedures to repair

For the tool that writes the catalogue's content, as [the depth brief](phase-3-depth-scenarios.md) was. It lists what failed when all 24 depth scenarios were run on the real reference host on 15 November 2026, by procedure ID. It contains no commands; the commands are yours to change.

The rule from the brief: every check must hold on a stock Debian 12 host. A step whose check fails there is fixed or removed, never kept as a hard one.

## What failed

| Procedure | File | Scenarios and steps | What the real host answered | What the repair has to achieve |
| --- | --- | --- | --- | --- |
| `d-log-make` | `96-depth-cover.yaml` | `depth-cover-attrs` s1, `depth-cover-files` s1, `depth-cover-logs` s5 | "No such file or directory" | It writes into a working directory that no step creates. An emulator lets that through; a real host does not. Either the procedure makes its directory first, or a step before it does. The one directory-making procedure in the set makes a different directory |
| `d-temp-make` | `96-depth-cover.yaml` | `depth-cover-logs` s8 | "No such file or directory" | The same directory, the same repair |
| `d-shadow-after` | `94-depth-rotate.yaml` | `depth-rotate-exec` m2, `depth-rotate-human` s3 and m4, `depth-rotate-shell` s2 | "event not found" | It passes over an exec channel and fails in an interactive shell, where bash's history expansion acts on part of its pattern. It has to be written so that an interactive shell leaves it alone |
| `d-debincnf-cred` | `91-depth-credfiles.yaml` | `depth-cred-app` s4, `depth-cred-daemons` s5, `depth-cred-shadow` s9, `depth-stack-db` s6 | Nothing, and no success marker | What it looks for is not in that file on Debian 12. The check has to be one a stock Debian 12 host satisfies, or the step goes |
| `d-pwd-holds` | `93-depth-files.yaml` | `depth-files-verify` s13 | Nothing, and no success marker | It expects the session to still be in a working directory at that point, and on the real host it is not. Either an earlier step has to leave the session there, or the check has to ask for what is true |
| `d-tar-www` | `92-depth-stack.yaml` | `depth-stack-db` s10 | Nothing, and no success marker | It writes its archive into a working directory that no step creates, and hides the error. The same repair as the first two |

One more was a missing tool, not a broken check, and is settled: `d-lsmod-shape` needs `kmod`, which the slim reference image lacks and a real Debian server has. It was added to the arm's image and that scenario passes.

## How to check a repair

On a lab host, with the stack running:

```bash
make arm-r-check
make lab-arm ARM=r ONLY=depth-cover-attrs
make arm-report ARM=r
make arm-failed ARM=r
```

`arm-report` says how far each session got. `arm-failed` shows, for every check that failed, the pattern and what the host answered; it does not keep the input. A changed procedure changes the depth catalogue's hash, so `uv run python -m eval.split depth-build` has to be run again before the lint will pass; that is allowed while the depth split is provisional.

## When done

All 24 scenarios pass every check on the reference host. The owner then freezes the split (`python -m eval.split depth-freeze`) and measures the before numbers on stock Cowrie and the phase 2 stack.
