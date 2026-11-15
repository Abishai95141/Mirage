# Intel workers: the live actor classifier (and the experiments' code, unused at run time).
# Build context is the repo root. The image carries model code and no model: the classifier's
# file is mounted read-only at run time, and without it the worker applies only the rule.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
# libgomp: LightGBM's OpenMP runtime.
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && apt-get clean
COPY schema/pyproject.toml schema/pyproject.toml
COPY schema/src schema/src
COPY lab/pyproject.toml lab/pyproject.toml
COPY lab/src lab/src
COPY intel/pyproject.toml intel/pyproject.toml
COPY intel/src intel/src
RUN pip install --no-cache-dir ./schema ./lab ./intel

USER 10001:10001
CMD ["mirage-classifier-worker"]
