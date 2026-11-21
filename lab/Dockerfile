# The scenario runner (docs/05-phase-2-spec.md). Build context is the repo root.
# It carries clients only: no decoy, pipeline or model code, and no scenario content (the
# catalogue and scenarios are mounted read-only at run time).
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY schema/pyproject.toml schema/pyproject.toml
COPY schema/src schema/src
COPY lab/pyproject.toml lab/pyproject.toml
COPY lab/src lab/src
RUN pip install --no-cache-dir ./schema ./lab \
 # The named volume copies this owner when first created, so the non-root runner can write.
 && mkdir -p /var/lib/mirage-lab /var/lib/mirage-arms \
 && chown 10001:10001 /var/lib/mirage-lab /var/lib/mirage-arms

USER 10001:10001
ENTRYPOINT ["mirage-lab"]
