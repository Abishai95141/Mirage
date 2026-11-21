# The tools that boot a hardware class as a throwaway virtual machine (run.sh). Nothing of
# MIRAGE is in this image; it is QEMU and an ISO writer on Debian 12.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils genisoimage python3 python3-yaml ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
