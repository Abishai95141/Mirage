#!/bin/bash
# What every program on the reference image says for --help and --version, in a throwaway
# container with no network (phase 3, step 5b). The candidates (candidates.py) are made from
# these texts: a program's options are read from its own help.
#
#   bash eval/tune/collect_help.sh OUT_DIR        (lab host; needs make reference-image)
#
# Writes OUT_DIR/<program>.{help,version}[.err|.code] and OUT_DIR/names.txt.
set -u
out="${1:?usage: collect_help.sh OUT_DIR}"
name=mirage-tune-help
mkdir -p "$out"
docker rm -f $name >/dev/null 2>&1
docker create --network none --name $name mirage/reference:debian-12 >/dev/null
trap 'docker rm -f $name >/dev/null 2>&1' EXIT
docker start $name >/dev/null
for _ in $(seq 1 60); do
  docker exec $name test -f /ready 2>/dev/null && break
  timeout 1 tail --pid=$$ -f /dev/null
done
docker exec $name sh -c "mkdir -p /h && ls /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin 2>/dev/null | grep -v : | grep . | sort -u > /h/names.txt; wc -l < /h/names.txt"
docker exec $name sh -c "
cd /h
while read -r p; do
  for flag in help version; do
    timeout 5 \$p --\$flag > \"\$p.\$flag\" 2> \"\$p.\$flag.err\" < /dev/null; echo \"\$?\" > \"\$p.\$flag.code\"
  done
done < names.txt
"
docker cp -q $name:/h/. "$out/"
ls "$out" | wc -l
