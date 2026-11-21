#!/bin/bash
# Write emulator-commands.json: every command the SSH decoy's image emulates and every
# program it has only a fixed text for, read from the image itself. Run it after a fork patch adds commands, before `make render-inventory`, or
# the inventory counts what the decoy has had for days as missing (found 18 November 2026).
#
#   bash decoys/profiles/rendered/sources/list-emulated.sh     (needs the built decoy image)
set -euo pipefail
cd "$(dirname "$0")"
image="${IMAGE:-mirage/cowrie:dev}"
name=mirage-list-emulated
docker rm -f "$name" >/dev/null 2>&1 || true
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker create --name "$name" -w /cowrie/cowrie-git --network none \
  --entrypoint /cowrie/cowrie-env/bin/python "$image" -c '
import importlib, json, pkgutil
import cowrie.commands as c
names = set()
for info in pkgutil.iter_modules(c.__path__):
    try:
        mod = importlib.import_module("cowrie.commands." + info.name)
    except Exception:
        continue
    names |= {k.rsplit("/", 1)[-1] for k in getattr(mod, "commands", {})}
import os
texts = set()
root = os.path.join(os.path.dirname(c.__path__[0]), "data", "txtcmds")
for d, _subdirs, files in os.walk(root):
    texts |= {os.path.relpath(os.path.join(d, f), root) for f in files}
print(json.dumps({"commands": sorted(n for n in names if not n.startswith("__")),
                  "txtcmds": sorted(texts)}))
' >/dev/null
commands="$(docker start -a "$name" 2>/dev/null | tail -1)"
patches="$(ls ../../../ssh/patches/*.patch | wc -l | tr -d ' ')"
python3 - "$commands" "$patches" <<'PY'
import datetime, json, sys
found = json.loads(sys.argv[1])
doc = {
    "from": f"the stack's SSH decoy image (Cowrie 3.1.6 with the {sys.argv[2]} MIRAGE patches), "
            f"{datetime.date.today():%-d %B %Y}",
    # What the emulator has a command class for, and the programs it only has a fixed text
    # for (Cowrie's own txtcmds; a deployment's hardware texts are its class's record).
    "commands": found["commands"],
    "txtcmds": found["txtcmds"],
}
open("emulator-commands.json", "w").write(json.dumps(doc, indent=1) + "\n")
print(f"{len(doc['commands'])} commands, {len(doc['txtcmds'])} fixed texts")
PY
