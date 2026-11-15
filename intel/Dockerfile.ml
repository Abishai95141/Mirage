# The learned tagger's worker: the intel package plus PyTorch (CPU) and sentence-transformers.
# Build context is the repo root. Built only when asked (`make ml-image`): it downloads about
# 0.5 GB of wheels. The image carries code and no weights: the embedding model is read from
# the host's Hugging Face cache, mounted read-only, and the tagger's index from build/models.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
# libgomp: the OpenMP runtime LightGBM and PyTorch use.
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && apt-get clean
# The versions the experiments ran with (uv.lock, group "research").
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.15.0 \
    && pip install --no-cache-dir transformers==5.23.0 sentence-transformers==6.3.0
COPY schema/pyproject.toml schema/pyproject.toml
COPY schema/src schema/src
COPY lab/pyproject.toml lab/pyproject.toml
COPY lab/src lab/src
COPY intel/pyproject.toml intel/pyproject.toml
COPY intel/src intel/src
RUN pip install --no-cache-dir ./schema ./lab ./intel

USER 10001:10001
CMD ["mirage-tagger-model-worker"]
