#!/usr/bin/env bash
# Run the lab host's make targets from a laptop on any network, over Tailscale.
#
#     tools/lab-host/remote.sh --check            is the lab host reachable, and how
#     tools/lab-host/remote.sh ps                 make ps, there
#     tools/lab-host/remote.sh showcase-up        open the public showcase link
#     tools/lab-host/remote.sh showcase-password  print the console's login (in your terminal)
#     tools/lab-host/remote.sh showcase-down      close it
#     tools/lab-host/remote.sh lab-run SCENARIOS=/lab/scenarios/demo
#     tools/lab-host/remote.sh --shell            a shell in the repository there
#     tools/lab-host/remote.sh --sync             copy this checkout there (sync.sh), same path
#     tools/lab-host/remote.sh --ssh-command      print the ssh command it uses
#
# The lab host must have joined your Tailscale network (on it: sudo bash
# tools/lab-host/remote-access.sh) and this laptop must be signed in to the same account.
# This file needs nothing else from the repository, so it can be copied to a laptop alone.
#
# Settings, all optional:
#   MIRAGE_LAB       the lab host's Tailscale name or address   (default mirage-lab)
#   MIRAGE_LAB_USER  the account on it                          (default abishai)
#   MIRAGE_LAB_DIR   the repository there                       (default mirage)
set -euo pipefail

LAB="${MIRAGE_LAB:-mirage-lab}"
LAB_USER="${MIRAGE_LAB_USER:-abishai}"
LAB_DIR="${MIRAGE_LAB_DIR:-mirage}"

# Tailscale on this laptop: the command, and the socket of the service it talks to. A
# service started by hand in userspace mode (as on a Mac without the app) has its own.
ts=()
find_tailscale() {
    local bin sock
    for bin in tailscale /Applications/Tailscale.app/Contents/MacOS/Tailscale; do
        command -v "$bin" >/dev/null 2>&1 || continue
        for sock in "" "$HOME/.tailscale/tailscaled.sock"; do
            if [ -z "$sock" ]; then
                "$bin" status >/dev/null 2>&1 && { ts=("$bin"); return 0; }
            elif [ -S "$sock" ]; then
                "$bin" --socket="$sock" status >/dev/null 2>&1 && { ts=("$bin" "--socket=$sock"); return 0; }
            fi
        done
    done
    return 1
}

# Is the lab host one of this laptop's Tailscale peers (by name or by address)?
is_peer() {
    [ "${#ts[@]}" -gt 0 ] || return 1
    case "$LAB" in 100.6[4-9].* | 100.[7-9][0-9].* | 100.1[01][0-9].* | 100.12[0-7].*) return 0 ;; esac
    "${ts[@]}" status 2>/dev/null | awk '{print $1; print $2}' | grep -qx "$LAB"
}

# How ssh reaches the lab host. Through `tailscale nc` when it is a Tailscale peer: that
# works whether or not this laptop routes Tailscale addresses itself. Otherwise plain ssh,
# which is right at home (MIRAGE_LAB=<its home address>) and where the Tailscale app does
# the routing and the naming.
#
# The first connection to a new name records the machine's key and later ones insist on it
# (accept-new). Tailscale has already proved which device answers. To insist on a key this
# laptop already trusts under another name, set MIRAGE_LAB_KEY_ALIAS to that name.
ssh_args=(-o ConnectTimeout=15 -o ServerAliveInterval=30 -o StrictHostKeyChecking=accept-new)
find_tailscale || true
if is_peer; then
    proxy="${ts[*]} nc %h %p"
    ssh_args+=(-o "ProxyCommand=$proxy")
fi
if [ -n "${MIRAGE_LAB_KEY_ALIAS:-}" ]; then
    ssh_args+=(-o "HostKeyAlias=$MIRAGE_LAB_KEY_ALIAS")
fi
target="$LAB_USER@$LAB"

# The ssh command on one line, in a form both a shell and rsync -e can split: an argument
# with spaces goes in double quotes.
ssh_command() {
    local out="ssh" a
    for a in "${ssh_args[@]}"; do
        case "$a" in
            *" "*) out="$out \"$a\"" ;;
            *) out="$out $a" ;;
        esac
    done
    printf '%s\n' "$out"
}

check() {
    local problems=0 out path
    echo "the lab host from here ($LAB):"
    if [ "${#ts[@]}" -eq 0 ]; then
        echo "  note  Tailscale is not running on this laptop; trying ssh directly"
    elif is_peer; then
        echo "  ok    it is on your Tailscale network"
        if path="$("${ts[@]}" ping --c 3 --timeout 5s "$LAB" 2>&1 | tail -1)"; then
            echo "  ok    it answers: $path"
        else
            echo "  FAIL  it does not answer over Tailscale: $path"
            problems=$((problems + 1))
        fi
    else
        echo "  note  it is not on your Tailscale network (on it: sudo bash"
        echo "        tools/lab-host/remote-access.sh); trying ssh directly"
    fi
    if out="$(ssh "${ssh_args[@]}" -o BatchMode=yes "$target" \
        "cd $LAB_DIR && echo \"\$(hostname): \$(docker ps --format '{{.Names}}' | grep -c '^mirage-') MIRAGE containers up\"" 2>&1)"; then
        echo "  ok    ssh works: $(echo "$out" | tail -1)"
    else
        echo "  FAIL  ssh does not work: $(echo "$out" | tail -1)"
        problems=$((problems + 1))
    fi
    echo
    echo "$problems problem(s)"
    return "$problems"
}

case "${1:-}" in
    "" | -h | --help)
        sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
        ;;
    --check)
        check
        ;;
    --shell)
        exec ssh -t "${ssh_args[@]}" "$target" "cd $LAB_DIR && exec \$SHELL -l"
        ;;
    --ssh-command)
        ssh_command
        ;;
    --sync)
        # Copy this checkout to the lab host over the same path (tools/lab-host/sync.sh).
        RSYNC_RSH="$(ssh_command)" exec "$(dirname "$0")/sync.sh" "$target" "$LAB_DIR"
        ;;
    -*)
        echo "unknown option $1; see $0 --help" >&2
        exit 2
        ;;
    *)
        # Every word is quoted for the far shell, so an argument cannot become a command.
        exec ssh -t "${ssh_args[@]}" "$target" \
            "export PATH=\$HOME/.local/bin:\$PATH; cd $LAB_DIR && make$(printf ' %q' "$@")"
        ;;
esac
