#!/usr/bin/env bash
# Mirror this checkout to a lab host: the files and the git history.
#
#     tools/lab-host/sync.sh user@host [directory on the host, default: mirage]
#
# The history goes too, so a run on the host records the commit that produced it, and
# "-dirty" if the files there differ from that commit (Makefile, CODE_VERSION). Copying the
# files alone left the host's history at an old commit, and every run recorded that one.
#
# Never copied: .env (the host has its own secrets), build/, data/ and every virtual
# environment. Nothing is deleted on the host outside its .git directory. Files that exist
# only there are listed at the end; a file this checkout has deleted (an old scenario, say)
# shows up in that list and would still be used there until it is removed by hand.
set -euo pipefail

HOST="${1:?usage: tools/lab-host/sync.sh user@host [directory]}"
DEST="${2:-mirage}"
# Where plain ssh does not reach the host (over Tailscale from a laptop that does not route
# it), set RSYNC_RSH to the ssh command to use; tools/lab-host/remote.sh --sync does. rsync
# reads that variable by itself.
REMOTE_SHELL="${RSYNC_RSH:-ssh}"
cd "$(git rev-parse --show-toplevel)"

rsync -az \
  --exclude '.git/' --exclude '.env' --exclude 'build/' --exclude 'data/' \
  --exclude '.venv*/' --exclude '__pycache__/' --exclude '.pytest_cache/' --exclude '.ruff_cache/' \
  ./ "$HOST:$DEST/"
rsync -az --delete .git/ "$HOST:$DEST/.git/"

echo "here: $(git describe --always --dirty --abbrev=7)"
# shellcheck disable=SC2029  # $DEST is meant to expand on this side
bash -c "$REMOTE_SHELL \"\$1\" \"\$2\"" _ "$HOST" \
  "cd '$DEST' && echo \"host: \$(git describe --always --dirty --abbrev=7)\" && git status --short | head -n 40"
