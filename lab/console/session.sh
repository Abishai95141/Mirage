#!/bin/sh
# One signed-in visitor's session: say what this is, then become the recorder. ttyd runs this
# once per browser connection, on a terminal of its own.
set -eu

# A ceiling on sessions per start of the console. Every recording takes a simulated address
# that is never handed out again (spec section 2), and the lab's own runs draw on the same
# range. One empty file per session; /tmp is this container's and is gone when it stops.
limit="${CONSOLE_MAX_SESSIONS:-300}"
mkdir -p /tmp/console-sessions
mktemp /tmp/console-sessions/s.XXXXXXXX >/dev/null
used=$(find /tmp/console-sessions -type f | wc -l)
if [ "$used" -gt "$limit" ]; then
    printf 'This showcase has used all %s of its console sessions.\r\n' "$limit"
    printf 'Ask whoever runs it to restart the showcase.\r\n'
    sleep 5
    exit 0
fi

minutes=$(( ${LAB_RECORD_MAX_S:-900} / 60 ))
printf '\r\n  MIRAGE showcase console\r\n\r\n'
printf '  You are about to get a root shell on the SSH decoy: a simulated server.\r\n'
printf '  Nothing you type runs on a real machine.\r\n'
printf '  Everything you type is recorded and shown on the public dashboards,\r\n'
printf '  so do not type anything private.\r\n'
printf '  The session ends when you exit the shell, press Ctrl-], or after %s minutes.\r\n\r\n' "$minutes"

# exec: the recorder must be the process ttyd signals when the browser goes away, so that a
# closed tab still leaves a session with its ground truth.
exec mirage-lab record --user root
