#!/bin/bash
# Rebuild the working copy of the Cowrie fork: the pinned release with the patch series of
# decoys/ssh/patches applied as one commit a patch, on a branch called mirage.
#
#   tools/fork-worktree.sh DEST [SOURCE]
#
# SOURCE is a clone of Cowrie that has v3.1.6 (default: the project's GitHub repository; a
# lab host's clean clone works too, e.g. abishai@HOST:mirage-scratch/ci-fork). The working
# copy is scratch: everything in it that matters is a patch in this repository. To change
# the fork, commit there and export again:
#
#   git format-patch -N --zero-commit -o <repo>/decoys/ssh/patches --start-number N <base>
#
# and set each new patch's From line to `MIRAGE <noreply@anthropic.com>` (as the others).
set -euo pipefail
dest="${1:?usage: fork-worktree.sh DEST [SOURCE]}"
source="${2:-https://github.com/cowrie/cowrie.git}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
[ ! -e "$dest" ] || { echo "$dest exists; remove it or name another place" >&2; exit 1; }
git clone -q --depth 1 --branch v3.1.6 "$source" "$dest" 2>/dev/null || git clone -q "$source" "$dest"
cd "$dest"
git rev-parse HEAD | grep -q "^ea9513e" || { echo "not the pinned release (ea9513e)" >&2; exit 1; }
git checkout -q -b mirage
for p in "$repo"/decoys/ssh/patches/*.patch; do
    if ! git -c user.name=MIRAGE -c user.email=noreply@anthropic.com am -q --whitespace=nowarn "$p" 2>/dev/null; then
        git am --abort 2>/dev/null || true
        git apply --whitespace=nowarn "$p"
        git add -A
        subject="$(sed -n 's/^Subject: \[PATCH\] //p' "$p" | head -1)"
        git -c user.name=MIRAGE -c user.email=noreply@anthropic.com commit -q -m "${subject:-$(basename "$p")}"
    fi
done
git log --oneline | head -3
echo "$(git rev-list --count ea9513e..HEAD) patches applied in $dest"
