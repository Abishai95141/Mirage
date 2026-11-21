#!/bin/bash
# Record what the four reference services listen on, and which descriptor of which process
# holds each socket. The decoy's `ss` (phase 3 spec 3.4) takes its service rows from this,
# as its `ps` takes them from processes.tsv.
#
#   bash decoys/profiles/reference/record-sockets.sh     (needs make reference-image)
#
# Writes decoys/profiles/reference/sockets.tsv. The container has no network and is removed.
# `ss` is asked from a privileged exec: without it root in a container may not read another
# user's /proc/PID/fd, and ss would name no process for MariaDB, Redis or nginx's workers,
# as it would not on a real host.
set -euo pipefail
cd "$(dirname "$0")"
name=mirage-reference-sockets
docker rm -f "$name" >/dev/null 2>&1 || true
docker create --name "$name" --network none mirage/reference:debian-12 >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker start "$name" >/dev/null
for _ in $(seq 1 90); do
  docker exec "$name" test -f /ready 2>/dev/null && break
  sleep 1
done
docker exec "$name" test -f /ready
sleep 5
{
  echo "# Written by record-sockets.sh from $(docker inspect --format '{{.Image}}' "$name" | cut -c1-19). Do not edit."
  echo "# netid	state	recv_q	send_q	local	port	peer	peer_port	comm	fd"
  # One row a socket: the process named is the first ss gives (every holder of a socket has
  # it at the same descriptor: nginx's workers inherit the master's).
  docker exec --privileged "$name" ss -Htulnp \
    | awk '{
        n = split($5, a, ":"); port = a[n]; local = substr($5, 1, length($5) - length(port) - 1)
        m = split($6, b, ":"); pport = b[m]; peer = substr($6, 1, length($6) - length(pport) - 1)
        comm = "-"; fd = "-"
        if (match($0, /users:\(\("[^"]+",pid=[0-9]+,fd=[0-9]+\)/)) {
          s = substr($0, RSTART, RLENGTH)
          split(s, q, "\""); comm = q[2]
          sub(/.*fd=/, "", s); sub(/\).*/, "", s); fd = s
        }
        print $1 "\t" $2 "\t" $3 "\t" $4 "\t" local "\t" port "\t" peer "\t" pport "\t" comm "\t" fd }'
  echo "# as ss printed it:"
  docker exec --privileged "$name" ss -tulnp | sed 's/^/# /; s/ *$//'
} > sockets.tsv
cat sockets.tsv
