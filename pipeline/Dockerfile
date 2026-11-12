# Pipeline image: normaliser, sessioniser and artifact indexer; compose picks the command and
# the healthcheck. Build context is the repo root (see compose/docker-compose.yml).
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY schema/pyproject.toml schema/pyproject.toml
COPY schema/src schema/src
COPY decoys/tokens/pyproject.toml decoys/tokens/pyproject.toml
COPY decoys/tokens/src decoys/tokens/src
COPY pipeline/pyproject.toml pipeline/pyproject.toml
COPY pipeline/src pipeline/src
RUN pip install --no-cache-dir ./schema ./decoys/tokens ./pipeline

USER 10001:10001
HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
  CMD ["python", "-c", "from mirage_pipeline.normaliser import healthcheck; healthcheck()"]
CMD ["mirage-normaliser"]
