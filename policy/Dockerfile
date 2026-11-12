# Policy service image. Build context is the repo root (see compose/docker-compose.yml).
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY schema/pyproject.toml schema/pyproject.toml
COPY schema/src schema/src
COPY policy/pyproject.toml policy/pyproject.toml
COPY policy/src policy/src
RUN pip install --no-cache-dir ./schema ./policy \
 && mkdir -p /var/log/mirage-policy && chown 10001:10001 /var/log/mirage-policy

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
  CMD ["python", "-c", "from mirage_policy.main import healthcheck; healthcheck()"]
CMD ["mirage-policy"]
