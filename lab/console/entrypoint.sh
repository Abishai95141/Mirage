#!/bin/sh
# Start the showcase's console: ttyd, serving one program (console-session) to people who
# know the password. Refuses to start without a real password or outside the lab network.
set -eu

if [ -z "${CONSOLE_PASSWORD:-}" ]; then
    echo "refusing to start: no console password (SHOWCASE_CONSOLE_PASSWORD in .env; run make env)" >&2
    exit 1
fi
if [ "${#CONSOLE_PASSWORD}" -lt 24 ]; then
    echo "refusing to start: the console password is shorter than 24 characters" >&2
    exit 1
fi
case "$CONSOLE_PASSWORD" in
    *[!A-Za-z0-9._~-]*)
        # The proxy in front reads the same password from its configuration, where other
        # characters would need quoting. `make env` only ever writes hex.
        echo "refusing to start: the console password may hold letters, digits and . _ ~ - only" >&2
        exit 1
        ;;
esac

# The recorder's own isolation check, once, before anything listens. Every session makes it
# again. LAB_SIDE_NETWORKS=1 is the console's rule: the lab network and the proxy's, both
# internal, and no route anywhere else.
mirage-lab check

# The password is handed to ttyd and taken out of the environment, so the sessions it starts
# do not carry it.
credential="presenter:${CONSOLE_PASSWORD}"
unset CONSOLE_PASSWORD

# --writable: without it ttyd only shows output. --check-origin: a page on another site
# cannot open a terminal with a signed-in visitor's browser. File transfer stays off (the
# default), so the only thing that crosses is keys in and screen out.
exec ttyd \
    --port 7681 \
    --base-path /console \
    --credential "$credential" \
    --max-clients "${CONSOLE_MAX_CLIENTS:-3}" \
    --writable \
    --check-origin \
    --terminal-type xterm-256color \
    --client-option titleFixed="MIRAGE console" \
    --client-option disableLeaveAlert=true \
    /usr/local/bin/console-session
