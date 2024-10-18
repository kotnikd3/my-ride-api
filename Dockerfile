FROM python:3.12-slim-bookworm AS base

WORKDIR /app

COPY requirements /app/requirements

RUN set -ex; \
    pip install --upgrade pip \
    # Install packages
    && pip install --no-cache-dir -r requirements/base.txt

EXPOSE 8000/tcp


# Development image to use with docker compose
FROM base AS local

RUN set -ex; \
    pip install --upgrade pip \
    # Install packages
    && pip install --no-cache-dir -r requirements/local.txt


# Base image to deploy to Google Cloud Platform
FROM base AS gcp-base

COPY my-ride-api /app/my-ride-api
COPY entrypoint.sh /app/

ENTRYPOINT ["./entrypoint.sh"]


# Development image to use with standalone docker
FROM gcp-base AS gcp-dev

RUN pip install --no-cache-dir -r requirements/dev.txt


# Production image
FROM gcp-base AS gcp-prod

RUN pip install --no-cache-dir -r requirements/prod.txt
