# One image for the decoys MIRAGE writes itself; each compose service picks its entry point
# (mirage-http-decoy, ...). Build context is the repo root.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY schema/pyproject.toml schema/pyproject.toml
COPY schema/src schema/src
COPY decoys/common/pyproject.toml decoys/common/pyproject.toml
COPY decoys/common/src decoys/common/src
COPY decoys/http/pyproject.toml decoys/http/pyproject.toml
COPY decoys/http/src decoys/http/src
RUN pip install --no-cache-dir ./schema ./decoys/common ./decoys/http \
 # Named volumes copy these owners when first created, so the non-root decoy can write.
 && mkdir -p /var/log/mirage /var/lib/mirage/artifacts \
 && chown 10001:10001 /var/log/mirage /var/lib/mirage/artifacts

USER 10001:10001
