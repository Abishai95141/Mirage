# syntax=docker/dockerfile:1
# MIRAGE SSH decoy: Cowrie v3.1.6 with the patch series in patches/, and a filesystem built
# for one deployment from the Debian 12 reference root and the rendered profile.
#
# Build context: the repository root. Extra context "profile": the rendered deployment
# (build/profile, from `make profile`). Image "mirage/reference:debian-12" must exist
# (`make profile-ref` builds it).

FROM cowrie/cowrie:3.1.6 AS stock

# 1. Apply the patch series to Cowrie's source and delete the FoxIO-licensed files.
FROM python:3.12-slim-bookworm AS patched
RUN apt-get update && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*
COPY --from=stock /cowrie/cowrie-git /cowrie/cowrie-git
COPY decoys/ssh/patches /patches
COPY decoys/ssh/remove.txt /remove.txt
WORKDIR /cowrie/cowrie-git
# The image ships Cowrie's tree without docs/, so the patches' documentation hunks are
# skipped here; CI applies the full series, docs included, to a clone of the same tag.
RUN for p in /patches/*.patch; do git apply --whitespace=nowarn --exclude='docs/*' "$p" || exit 1; done \
 && grep -v '^#' /remove.txt | grep . | xargs rm -rf

# 2. Walk the reference root with Cowrie's createfs and apply the profile.
FROM mirage/reference:debian-12 AS refroot
FROM cowrie/cowrie:3.1.6 AS fsbuild
USER 0
COPY --from=refroot / /refroot/
COPY --from=patched /cowrie/cowrie-git/src /patched-src
COPY --from=profile cowrie /profile-cowrie
COPY decoys/ssh/build_fs.py /build_fs.py
ENV PYTHONPATH=/patched-src
RUN ["/cowrie/cowrie-env/bin/python3", "/build_fs.py", "/refroot", "/profile-cowrie", "/fsout"]

# 3. The decoy: stock image, patched source, this deployment's filesystem and config.
FROM cowrie/cowrie:3.1.6
USER 0
# The stock image has no shell; remove the unpatched source with Cowrie's own interpreter.
RUN ["/cowrie/cowrie-env/bin/python3", "-c", "import shutil; shutil.rmtree('/cowrie/cowrie-git/src')"]
COPY --from=patched --chown=999:999 /cowrie/cowrie-git/src /cowrie/cowrie-git/src
COPY --from=fsbuild --chown=999:999 /fsout /cowrie/deployment
COPY --from=profile --chown=999:999 cowrie/userdb.txt /cowrie/deployment/etc/userdb.txt
COPY --from=profile --chown=999:999 cowrie/cowrie.cfg /etc/cowrie/cowrie.cfg
USER 999:999
