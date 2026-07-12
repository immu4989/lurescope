FROM python:3.11-slim

# git is needed to install the lurebench dependency from its repo.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .

EXPOSE 8000
# 0.0.0.0 so the container is reachable; override host/port via the CLI if needed.
CMD ["uvicorn", "lurescope.app:app", "--host", "0.0.0.0", "--port", "8000"]
