FROM python:3.11-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Git is a build-only dependency for the commit-pinned LureBench wheel.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY lurescope ./lurescope
COPY spec ./spec
RUN pip install --prefix=/install .


FROM python:3.11-slim AS runtime

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 lurescope \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin lurescope

WORKDIR /app
COPY --from=builder /install /usr/local

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()"]

CMD ["uvicorn", "lurescope.app:app", "--host", "0.0.0.0", "--port", "8000"]
