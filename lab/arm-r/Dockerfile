# Arm R of phase 3's depth comparison (docs/06-phase-3-spec.md, section 5): the reference
# Debian host, made to look like the host a deployment's profile describes. Build context is
# this directory. Needs mirage/reference:debian-12 (make reference-image).
FROM mirage/reference:debian-12
# Tools a depth scenario asked for that the slim reference image lacks and a real Debian server
# has. Each is a decision (spec 3.0): kmod, for listing kernel modules.
RUN apt-get update \
 && apt-get install -y --no-install-recommends kmod \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /arm-entrypoint.sh
COPY containment.sh /arm-containment.sh
CMD ["/bin/sh", "/arm-entrypoint.sh"]
