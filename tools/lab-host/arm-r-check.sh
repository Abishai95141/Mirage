#!/usr/bin/env bash
# Containment of arm R, the real reference host of phase 3's depth comparison, checked from
# inside it before any scenario is sent there (phase 3 spec, section 5 and 3.5's acceptance).
#
#     tools/lab-host/arm-r-check.sh        (on a lab host, from the repository, stack running)
#
# What is sent to that host really runs as root, so the container must be able to reach
# nothing: not the internet, not this machine, not the decoys, the policy service or the
# store. One target must answer, the lab edge in front of it: without that positive control a
# probe that could reach nothing at all would pass for isolation.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
COMPOSE="docker compose --env-file .env -f compose/docker-compose.yml --profile lab --profile arms"

$COMPOSE up -d --force-recreate --wait arm-r arm-r-edge >/dev/null 2>&1 ||
  { echo "the reference host did not start"; exit 1; }
trap '$COMPOSE rm -sf arm-r arm-r-edge >/dev/null 2>&1' EXIT

ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$1" 2>/dev/null | awk '{print $1}'; }
gateway_of() { docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' "$1" 2>/dev/null; }

must_answer=("arm-r-edge:2222")
must_not=("1.1.1.1:443" "8.8.8.8:53" "9.9.9.9:443")
host_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -n "$host_ip" ] && must_not+=("$host_ip:22")
for net in bridge mirage_arm mirage_lab mirage_decoy mirage_gate mirage_core mirage_edge; do
  gw=$(gateway_of "$net")
  # The arm network has no address on this machine, and says so in place of one.
  [[ "$gw" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && must_not+=("$gw:22")
done
gw=$(gateway_of mirage_arm)
[[ "$gw" =~ ^[0-9.]+$ ]] && { echo "PROBLEM: the arm network has an address on this machine ($gw)"; exit 1; }
for pair in mirage-policy-1:8000 mirage-clickhouse-1:8123 mirage-cowrie-1:2222 mirage-nats-1:4222 mirage-lab-edge-1:2222; do
  ip=$(ip_of "${pair%:*}")
  [ -n "$ip" ] && must_not+=("$ip:${pair##*:}")
done

results=$($COMPOSE exec -T arm-r sh /arm-containment.sh "${must_answer[@]}" "${must_not[@]}")
echo "$results"
bad=0
for t in "${must_answer[@]}"; do
  grep -qx "$t connected" <<<"$results" || { echo "PROBLEM: the positive control $t did not answer"; bad=1; }
done
for t in "${must_not[@]}"; do
  grep -qx "$t blocked" <<<"$results" || { echo "PROBLEM: the reference host can reach $t"; bad=1; }
done
[ "$bad" -eq 0 ] && echo "contained: ${#must_not[@]} targets blocked, the lab edge answers"
exit "$bad"
