# syntax=docker/dockerfile:1
#
# Container image for the intentionally-vulnerable demo app.
# The Dockerfile itself follows good practice (pinned base, non-root user,
# healthcheck) — the vulnerabilities live in the application and its
# dependencies, which is exactly what the pipeline is meant to surface.

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Apply the latest OS security patches available for the base image. Base-image
# CVEs are a moving target; rebuilding regularly picks up whatever fixes Debian
# has published. CVEs with no upstream fix yet are handled by Trivy's
# `ignore-unfixed` in the pipeline (we report them, but don't block on what we
# cannot action).
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user rather than root.
RUN groupadd --system app && useradd --system --gid app --home-dir /app app

WORKDIR /app

# Install dependencies first so this layer is cached across code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code and hand ownership to the unprivileged user.
COPY app.py .
RUN chown -R app:app /app

USER app

EXPOSE 5000

# Simple liveness probe against the /health endpoint.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health').status==200 else 1)"

# Serve the Flask `app` object with gunicorn (production-style WSGI server).
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
