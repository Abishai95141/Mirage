#!/usr/bin/env bash
# Give the running kernel its NVIDIA module, so that the model server can start again.
#
#     sudo bash tools/lab-host/gpu-driver.sh
#
# When to run it: `make llm-up` fails with "nvml error: driver not loaded", or `nvidia-smi`
# says it cannot communicate with the driver. That happens when the host restarts into a
# kernel newer than the one its NVIDIA module package was installed for: Ubuntu ships the
# module as one package per kernel (linux-modules-nvidia-<series>-<kernel>), and an update
# can bring the new kernel without it (found on 20 November 2026: kernel 7.0.0-43, module
# package still 6.17.0-29's).
#
# What it does: installs the module package of the installed driver series for the kernel
# that is running (about 8 MB, from Ubuntu's own archive, signed for Secure Boot), loads it,
# and prints what nvidia-smi sees. It changes nothing else, and does nothing if the driver
# already answers.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "run it with sudo: sudo bash tools/lab-host/gpu-driver.sh" >&2
    exit 1
fi
if nvidia-smi > /dev/null 2>&1; then
    echo "the driver is loaded; nothing to do"
    nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
    exit 0
fi

kernel="$(uname -r)"
series="$(dpkg-query -W -f='${Status} ${Package}\n' 'nvidia-driver-*' 2> /dev/null |
    sed -n 's/^install ok installed nvidia-driver-//p' | head -1)"
if [ -z "$series" ]; then
    echo "no nvidia-driver-* package is installed; this script only repairs an existing install" >&2
    exit 1
fi
package="linux-modules-nvidia-${series}-${kernel}"
echo "kernel ${kernel}, driver series ${series}: installing ${package}"
apt-get update -q
if ! apt-cache show "$package" > /dev/null 2>&1; then
    echo "Ubuntu has no ${package} yet. Until it does, start the host on the previous kernel" >&2
    echo "(Advanced options in the boot menu), or run the showcase without the model." >&2
    exit 1
fi
apt-get install -y "$package"
modprobe nvidia
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader
echo "done: make llm-up will work now"
