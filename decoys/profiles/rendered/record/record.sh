#!/usr/bin/env bash
# Record what a real Debian 12 server prints for the render library's commands (phase 3 spec
# 3.2a, rendering step 1). The commands are the render inventory's reporting commands; each
# runs in a throwaway container of the reference image that has no network at all, and the
# container is removed afterwards. Needs Docker and `make reference-image`. No root.
#
#   decoys/profiles/rendered/record/record.sh        writes build/rendered/reference
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
out="$root/build/rendered/reference"
image=mirage/reference:debian-12
name=mirage-render-record

docker image inspect "$image" > /dev/null 2>&1 || {
    echo "no $image: run 'make reference-image' first" >&2
    exit 1
}
commands=$(mktemp)
cleanup() {
    docker rm -f "$name" > /dev/null 2>&1 || true
    rm -f "$commands"
}
trap cleanup EXIT
(cd "$root" && uv run mirage-profile render-library --commands) > "$commands"
[ -s "$commands" ] || {
    echo "the inventory names no command to record" >&2
    exit 1
}

docker rm -f "$name" > /dev/null 2>&1 || true
docker create --network none --name "$name" "$image" > /dev/null
docker start "$name" > /dev/null
for _ in $(seq 1 90); do
    docker exec "$name" test -f /ready 2> /dev/null && break
    sleep 1
done
docker exec "$name" test -f /ready || {
    echo "the reference host did not come up" >&2
    exit 1
}
docker exec "$name" mkdir -p /record
docker cp -q "$here/guest.sh" "$name:/record/guest.sh"
docker cp -q "$commands" "$name:/record/commands.txt"
docker exec "$name" chmod 644 /record/commands.txt
docker exec "$name" /bin/sh /record/guest.sh

rm -rf "$out"
mkdir -p "$out"
docker cp -q "$name:/record/out/." "$out/"
docker image inspect "$image" --format '{{.Id}}' > "$out/image.txt"
echo "recorded $(find "$out" -name '*.cmd' | wc -l | tr -d ' ') commands in $out"
