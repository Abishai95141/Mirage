#!/bin/bash
# Record what the four reference services look like as processes: who runs each, how much
# memory it holds, whether it is threaded. The decoy's process list (phase 3 spec 3.4) takes
# these figures; the command lines it shows come from the packages' systemd units, because
# this container starts the services by hand and a real host starts them from the units.
#
#   bash decoys/profiles/reference/record-processes.sh     (needs make reference-image)
#
# Writes decoys/profiles/reference/processes.tsv. The container has no network and is removed.
set -euo pipefail
cd "$(dirname "$0")"
name=mirage-reference-processes
docker rm -f "$name" >/dev/null 2>&1 || true
docker create --name "$name" --network none mirage/reference:debian-12 >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker start "$name" >/dev/null
for _ in $(seq 1 90); do
  docker exec "$name" test -f /ready 2>/dev/null && break
  sleep 1
done
docker exec "$name" test -f /ready
sleep 5  # let the services settle to their idle size
{
  echo "# Written by record-processes.sh from $(docker inspect --format '{{.Image}}' "$name" | cut -c1-19). Do not edit."
  echo "# user	vsz_kb	rss_kb	threads	stat	comm	args"
  docker exec "$name" ps -eo user:32,vsz,rss,nlwp,stat,comm:20,args --no-headers \
    | awk '$6 ~ /^(sshd|nginx|mariadbd|redis-server)$/ {
        args=""; for (i = 7; i <= NF; i++) args = args (i > 7 ? " " : "") $i;
        print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6 "\t" args }'
  # A shell and a ps of the session's own, for the rows the decoy adds for whoever is logged
  # in. The trailing `true` keeps bash from replacing itself with the ps.
  docker exec "$name" bash -c 'ps -o user:32=,vsz=,rss=,nlwp=,stat=,comm:20=,args= -p $$; true' \
    | awk '{ print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\tbash\t-bash" }'
  docker exec "$name" ps -o user:32=,vsz=,rss=,nlwp=,stat=,comm:20=,args= -C ps \
    | awk 'NR == 1 { print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\tps\tps" }'
  for unit in nginx redis-server mariadb ssh; do
    docker exec "$name" sh -c "grep -E '^(ExecStart|User)=' /lib/systemd/system/$unit.service" \
      | sed "s|^|# unit $unit: |"
  done
} > processes.tsv
cat processes.tsv
