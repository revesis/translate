# Google Translate local API -- no browser, no third-party deps.
# Build:  podman build --format docker -t gt-api:1.0 .     (or: docker build -t gt-api:1.0 .)
# Run:    docker compose up -d
FROM python:3.12-slim

# Unbuffered stdout for `docker logs`; no .pyc so a read-only rootfs stays clean.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    HOME=/tmp \
    GT_HOST=0.0.0.0 \
    GT_PORT=8770 \
    GT_DEFAULT_TL=zh-CN

WORKDIR /app

# Stdlib only: no pip install, no lockfile, nothing to build.
COPY gt_client.py gt_server.py gt.py ./

# Numeric UID: the slim image ships no useradd, and nothing needs a passwd entry.
USER 10001:10001

EXPOSE 8770

# The image has no curl/wget -- probe with Python itself. /health is never
# authenticated, so this works even with GT_API_KEY set.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python3", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8770/health', timeout=3).status == 200 else 1)"]

ENTRYPOINT ["python3", "-u", "gt_server.py"]
