#!/usr/bin/env bash
# Give this lab host a private address that its owner's own devices can reach from any
# network, so the stack can be started and stopped from far away (tools/lab-host/remote.sh).
#
# It installs Tailscale with Tailscale's own installer, starts it, and joins this machine to
# the owner's Tailscale network under the name "mirage-lab". Joining prints a sign-in link:
# open it and sign in with the account your other devices use.
#
# Run it on the lab host, as root, in your own terminal (it asks for your password):
#
#     sudo bash tools/lab-host/remote-access.sh
#
# What it changes on this machine: the tailscale package and its service, and one network
# interface (tailscale0). What it does not do: it does not turn on Tailscale's own SSH server,
# does not publish anything to the internet (no Funnel), does not route other machines'
# traffic, and does not touch sshd, the firewall rules you wrote, Docker or k3s.
#
# Who can then reach what: only devices signed in to the same Tailscale account, and only
# what this machine already offers on all its addresses (listed at the end). Everything the
# MIRAGE stack binds to 127.0.0.1 stays on 127.0.0.1.
#
# To undo:  sudo tailscale logout && sudo apt-get remove tailscale
set -euo pipefail

NAME="${MIRAGE_LAB_NAME:-mirage-lab}"

if [ "$(id -u)" -ne 0 ]; then
    echo "run this as root:  sudo bash $0" >&2
    exit 1
fi

if ! command -v tailscale >/dev/null 2>&1; then
    echo "== installing Tailscale (https://tailscale.com/install.sh)"
    installer="$(mktemp)"
    trap 'rm -f "$installer"' EXIT
    curl -fsSL https://tailscale.com/install.sh -o "$installer"
    sh "$installer"
else
    echo "== Tailscale is already installed: $(tailscale version | head -1)"
fi

systemctl enable --now tailscaled >/dev/null

state() { tailscale status --json 2>/dev/null | sed -n 's/.*"BackendState": *"\([A-Za-z]*\)".*/\1/p' | head -1; }

if [ "$(state)" != "Running" ]; then
    echo "== joining your Tailscale network as \"$NAME\""
    echo "   A sign-in link follows. Open it in a browser and sign in with the account your"
    echo "   other devices use. This waits until you have."
    # No --ssh, no --advertise-*, no --accept-routes: this machine only becomes reachable.
    tailscale up --hostname="$NAME"
else
    echo "== already joined"
fi

if [ "$(state)" != "Running" ]; then
    echo "not joined: tailscale reports \"$(state)\". Run this script again." >&2
    exit 1
fi

address="$(tailscale ip -4 | head -1)"
echo
echo "== done. This machine is \"$NAME\" at $address on your Tailscale network."
echo
echo "   What your other Tailscale devices can now reach here (ports open on every address):"
ss -ltnH 2>/dev/null | awk '{print $4}' | grep -E '^(0\.0\.0\.0|\*|\[::\]):' \
    | sed -E 's/.*://' | sort -un | tr '\n' ' ' | sed 's/^/     /'
echo
echo
echo "   Two things left, both yours:"
echo "   1. In Tailscale's admin page (Machines), open the menu on \"$NAME\" and choose"
echo "      \"Disable Key Expiry\". Otherwise this machine drops off after about 180 days."
echo "   2. From a laptop, on any network:  tools/lab-host/remote.sh --check"
