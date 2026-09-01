FROM python:3.11-slim@sha256:f1fd7707d6823c38591aa16ebaa0bc6892b609835a73520ad18a39e2e7454fc5 AS builder

COPY --from=ghcr.io/astral-sh/uv:0.12.3@sha256:2d890623d310b57771ce840f0da5eed5fc6d657da05ffaa45d82797b53fa3abc \
    /uv /uvx /bin/

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev --no-install-project
COPY lurescope ./lurescope
COPY spec ./spec
RUN uv sync --frozen --no-dev --no-editable


FROM python:3.11-slim@sha256:f1fd7707d6823c38591aa16ebaa0bc6892b609835a73520ad18a39e2e7454fc5 AS runtime

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

RUN groupadd --gid 10001 lurescope \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin lurescope

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()"]

CMD ["uvicorn", "lurescope.app:app", "--host", "0.0.0.0", "--port", "8000"]
