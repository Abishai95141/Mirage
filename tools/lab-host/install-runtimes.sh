#!/usr/bin/env bash
# Root steps for a MIRAGE lab host (phase 3 spec, 3.0): the two container runtimes phase 3
# needs and Docker does not ship.
#
#   - NVIDIA container toolkit: lets a container use the host's GPU (the model server, 3.2).
#   - gVisor (runsc): the sandbox runtime an escalated session runs under (3.5).
#
# Run it yourself, on the lab host, from the repository:
#
#     sudo bash tools/lab-host/install-runtimes.sh
#
# What it changes: two apt repositories and their signing keys are added, the packages are
# installed, both runtimes are added to /etc/docker/daemon.json (a copy of the old file is
# kept beside it), and Docker is restarted once. The default runtime stays runc. It does not
# touch the firewall, SSH, or any container's configuration.
#
# The restart stops every running container. Those with a restart policy come back by
# themselves (MIRAGE's do); run `make up` afterwards to be sure. A stopped container whose
# restart policy is "always" would be started by the restart, so the script refuses to go on
# if it finds one, and names it.
#
# Safe to run twice. Nothing here is specific to one deployment and it holds no secret.
# Sources: docs.nvidia.com/datacenter/cloud-native/container-toolkit (install guide) and
# gvisor.dev/docs/user_guide/install, both read on 15 November 2026.
set -euo pipefail

NVIDIA_CONTAINER_TOOLKIT_VERSION="${NVIDIA_CONTAINER_TOOLKIT_VERSION:-1.20.2-1}"
RUNSC_VERSION="${RUNSC_VERSION:-}"       # empty: the repository's current release
TEST_IMAGE="${TEST_IMAGE:-ubuntu:24.04}" # pulled for the two checks at the end (about 30 MB)
ASSUME_YES=0
[ "${1:-}" = "-y" ] && ASSUME_YES=1

say() { printf '\n== %s\n' "$*"; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || die "run with sudo"
command -v apt-get >/dev/null || die "this script is for Debian and Ubuntu (apt)"
command -v docker >/dev/null || die "Docker is not installed"
docker info >/dev/null 2>&1 || die "the Docker daemon is not running"
[ "$(dpkg --print-architecture)" = "amd64" ] || die "written for amd64"

HAVE_GPU=1
if ! command -v nvidia-smi >/dev/null || ! nvidia-smi >/dev/null 2>&1; then
  HAVE_GPU=0
  echo "note: nvidia-smi does not work here, so the NVIDIA container toolkit is skipped (install the GPU driver first)"
fi

# A stopped container with restart policy "always" is started when the daemon restarts.
surprises=""
while read -r name; do
  [ -n "$name" ] || continue
  if [ "$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$name")" = "always" ]; then
    surprises="$surprises $name"
  fi
done < <(docker ps -a --filter status=exited --filter status=created --format '{{.Names}}')
if [ -n "$surprises" ]; then
  echo "These stopped containers have restart policy \"always\" and would be started by the restart:$surprises" >&2
  die "set their policy to \"no\" (docker update --restart=no NAME) or remove them, then run this again"
fi

running_before=$(docker ps --format '{{.Names}}' | sort)
say "Plan"
if [ "$HAVE_GPU" -eq 1 ]; then
  echo "Install nvidia-container-toolkit $NVIDIA_CONTAINER_TOOLKIT_VERSION."
fi
echo "Install gVisor's runsc (${RUNSC_VERSION:-the current release})."
echo "Add the runtimes to /etc/docker/daemon.json and restart Docker once."
echo "$(printf '%s\n' "$running_before" | grep -c . || true) containers are running; they stop, and those with a restart policy come back."
if [ "$ASSUME_YES" -ne 1 ]; then
  read -r -p "Go on? [y/N] " answer
  case "$answer" in
    y | Y) ;;
    *) die "stopped; nothing was changed" ;;
  esac
fi

export DEBIAN_FRONTEND=noninteractive
backup=""
if [ -f /etc/docker/daemon.json ]; then
  backup="/etc/docker/daemon.json.before-mirage-runtimes.$(date +%Y%m%d%H%M%S)"
  cp -p /etc/docker/daemon.json "$backup"
  echo "kept a copy of the Docker configuration: $backup"
else
  echo "there is no /etc/docker/daemon.json yet; one will be created"
fi

say "Repositories"
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gnupg
if [ "$HAVE_GPU" -eq 1 ]; then
  curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey |
    gpg --batch --yes --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
  curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list |
    sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
      >/etc/apt/sources.list.d/nvidia-container-toolkit.list
fi
curl -fsSL https://gvisor.dev/archive.key |
  gpg --batch --yes --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  >/etc/apt/sources.list.d/gvisor.list
apt-get update

if [ "$HAVE_GPU" -eq 1 ]; then
  say "NVIDIA container toolkit"
  v="$NVIDIA_CONTAINER_TOOLKIT_VERSION"
  apt-get install -y \
    "nvidia-container-toolkit=$v" "nvidia-container-toolkit-base=$v" \
    "libnvidia-container-tools=$v" "libnvidia-container1=$v"
  # Adds the "nvidia" runtime to daemon.json. It does not make it the default.
  nvidia-ctk runtime configure --runtime=docker
fi

say "gVisor"
apt-get install -y "runsc${RUNSC_VERSION:+=$RUNSC_VERSION}"
# Adds the "runsc" runtime to daemon.json (the package may already have done so).
"$(command -v runsc)" install

say "Docker configuration"
python3 - <<'PY' || die "daemon.json is not what was expected; Docker was not restarted. Restore the copy named above if it looks wrong."
import json

with open("/etc/docker/daemon.json") as f:
    config = json.load(f)
assert config.get("default-runtime", "runc") == "runc", "the default runtime is no longer runc"
print("runtimes in daemon.json:", ", ".join(sorted(config.get("runtimes", {}))))
PY

say "Restarting Docker"
systemctl restart docker
for _ in $(seq 1 60); do
  docker info >/dev/null 2>&1 && break
  sleep 1
done
docker info >/dev/null 2>&1 ||
  die "Docker did not come back. See: journalctl -u docker -n 50. The previous configuration: ${backup:-there was none; remove /etc/docker/daemon.json}"

say "Checks"
runtimes=$(docker info --format '{{range $name, $_ := .Runtimes}}{{$name}} {{end}}')
echo "runtimes: $runtimes"
echo "default runtime: $(docker info --format '{{.DefaultRuntime}}')"
case " $runtimes " in
  *" runsc "*) ;;
  *) die "runsc is not registered with Docker" ;;
esac
# Under gVisor the kernel log is gVisor's own, which shows the sandbox kernel answered.
boot=$(docker run --rm --runtime=runsc "$TEST_IMAGE" dmesg)
printf '%s\n' "$boot" | head -n 3
printf '%s\n' "$boot" | grep -qi gvisor || die "the container did not run under gVisor"
echo "gVisor: ok"
if [ "$HAVE_GPU" -eq 1 ]; then
  case " $runtimes " in
    *" nvidia "*) ;;
    *) die "the nvidia runtime is not registered with Docker" ;;
  esac
  docker run --rm --gpus all "$TEST_IMAGE" nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
  echo "GPU in a container: ok"
fi

say "Installed"
dpkg-query -W -f='${Package} ${Version}\n' runsc nvidia-container-toolkit 2>/dev/null || true
sleep 5
missing=$(comm -23 <(printf '%s\n' "$running_before") <(docker ps --format '{{.Names}}' | sort) | grep . || true)
if [ -n "$missing" ]; then
  echo "Not running any more (no restart policy, or still starting):"
  printf '  %s\n' $missing
fi
echo "Now, as your own user, in the repository: make up"
