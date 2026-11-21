# The showcase's console (docs/08-showcase.md): a terminal in a browser, behind a password,
# whose only program is the human recorder (`mirage-lab record`). Whoever signs in types into
# the SSH decoy through the lab edge, exactly as `make lab-human` does from a shell.
# Build context is this directory. Needs mirage/lab:dev (make showcase-image builds both).
FROM mirage/lab:dev

USER root
# ttyd 1.7.7 (MIT, https://github.com/tsl0922/ttyd): the statically linked release binary,
# pinned by its SHA-256. Debian 12 does not package it. Only an x86-64 binary is pinned,
# because the showcase runs on the lab host and nowhere else.
ARG TARGETARCH
RUN test "$TARGETARCH" = amd64 \
 || { echo "the console image is built for an x86-64 lab host, not $TARGETARCH" >&2; exit 1; }
ADD --checksum=sha256:8a217c968aba172e0dbf3f34447218dc015bc4d5e59bf51db2f2cd12b7be4f55 \
    --chmod=0755 \
    https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64 /usr/local/bin/ttyd
COPY --chmod=0755 entrypoint.sh /usr/local/bin/console-entrypoint
COPY --chmod=0755 session.sh /usr/local/bin/console-session

USER 10001:10001
ENTRYPOINT ["/usr/local/bin/console-entrypoint"]
