FROM python:3.11-slim@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff AS assets

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY requirements-space.txt ./
RUN python -m pip install --root-user-action=ignore --no-deps --require-hashes --target /opt/wheel \
    --requirement requirements-space.txt
RUN python -c \
    "import shutil; shutil.copytree('/opt/wheel/lurescope/static', '/site/static'); shutil.copy2('/site/static/index.html', '/site/index.html')"
COPY model.json /site/static/model.json


FROM python:3.11-slim@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=7860

RUN groupadd --gid 10001 lurescope \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin lurescope
WORKDIR /app
COPY server.py ./server.py
COPY --from=assets /site ./site

USER 10001:10001
EXPOSE 7860
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7860/health', timeout=3).read()"]
CMD ["python", "server.py"]
