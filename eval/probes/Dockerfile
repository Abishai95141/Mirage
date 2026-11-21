# The fingerprint suite (docs/06-phase-3-spec.md, 3.4). Build context is the repo root.
# It carries clients and the fidelity check: no decoy, pipeline or model code. The layout under
# /app mirrors the repository's, because the probes read the recorded reference by that path.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY schema/pyproject.toml schema/pyproject.toml
COPY schema/src schema/src
COPY decoys/tokens/pyproject.toml decoys/tokens/pyproject.toml
COPY decoys/tokens/src decoys/tokens/src
COPY decoys/profiles/pyproject.toml decoys/profiles/pyproject.toml
COPY decoys/profiles/src decoys/profiles/src
RUN pip install --no-cache-dir ./schema ./decoys/tokens ./decoys/profiles "paramiko>=3.5" "pymysql>=1.1"
COPY decoys/profiles/reference/debian-12.json decoys/profiles/reference/debian-12.json
COPY eval/__init__.py eval/__init__.py
COPY eval/probes eval/probes

USER 10001:10001
ENTRYPOINT ["python", "-m", "eval.probes.suite"]
