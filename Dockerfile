# Google Translate local API, with image OCR.
#
# Text translation is pure stdlib HTTP. Image OCR additionally needs a browser:
# Google only returns the OCR text when the batchexecute call carries a botguard
# token, and that token can only be minted inside a real browser realm. Chromium
# therefore runs as a child process of the API itself - one container, no second
# service, no published port for the browser.
#
# Build:  podman build --format docker -t gt-api:1.0 .
# Run:    docker compose up -d
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    HOME=/tmp \
    GT_HOST=0.0.0.0 \
    GT_PORT=8770 \
    GT_DEFAULT_TL=zh-CN \
    # in-process signer: chromium as a child process, no HTTP hop
    GT_BROWSER=/usr/bin/chromium \
    GT_SIGNER_URL="" \
    GT_PROFILE_DIR=/tmp/bgr-inproc

# chromium for the botguard realm; fonts so its canvas/font probes look like a
# desktop; the rest are chromium's runtime deps that slim does not ship.
# One layer: deleting files in a later RUN does not shrink the image.
# The mesa software-GL stack (~192 MB of libLLVM/libgallium/libz3) is dropped;
# chromium then renders through its bundled swiftshader. Verified against the real
# RPC: the token is still accepted. chrome_crashpad_handler must stay or chromium
# aborts at start-up, and libVkLayer_khronos_validation.so is debug-only.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      chromium \
      ca-certificates \
      fonts-liberation \
      fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /usr/lib/chromium/libVkLayer_khronos_validation.so \
 && rm -rf /usr/share/doc /usr/share/man /usr/share/lintian \
 && (dpkg --purge --force-depends \
        libgl1-mesa-dri mesa-libgallium libglx-mesa0 libllvm19 libz3-4 >/dev/null 2>&1 || true) \
 && apt-get clean

# Only the signer needs a third-party package (CDP over websockets).
RUN pip install --no-cache-dir "websockets>=12,<14"

WORKDIR /app
COPY gt_client.py gt_server.py gt.py gt_image.py bgr_sidecar.py ./

# Numeric UID: the slim image ships no useradd, and nothing needs a passwd entry.
USER 10001:10001

EXPOSE 8770

# The image has no curl/wget -- probe with Python itself. /health is never
# authenticated, so this works even with GT_API_KEY set.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python3", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8770/health', timeout=3).status == 200 else 1)"]

ENTRYPOINT ["python3", "-u", "gt_server.py"]
