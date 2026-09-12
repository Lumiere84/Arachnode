# Arachnode AI Policy Engine — production image.
#
# Build:  docker build -t arachnode-engine .
# Run:    docker run -p 8000:8000 --env-file .env -v arachnode-data:/data arachnode-engine
#
# Notes:
# - Runs under gunicorn, not the Flask dev server — debug=False, so the
#   /admin/rogue-edit and /admin/corrupt-block demo endpoints are
#   inert (404) here, same as they are outside DEBUG anywhere else.
# - The sqlite file lives at /data/arachnode.db, on a named volume, so
#   it survives container recreation. Mount that volume in production;
#   without it every restart starts from an empty (freshly seeded) DB.
# - This image is meant to sit behind something that authenticates
#   callers before they reach it (a reverse proxy, an API gateway,
#   mTLS) — see the README's "Deployment" section. It has no built-in
#   session auth of its own; the Discernment Key is a second factor on
#   top of that boundary, not a replacement for it.

FROM python:3.12-slim

WORKDIR /srv/arachnode

RUN groupadd --system arachnode && useradd --system --gid arachnode --home /srv/arachnode arachnode \
    && mkdir -p /data && chown arachnode:arachnode /data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R arachnode:arachnode /srv/arachnode

ENV ARACHNODE_DATABASE_PATH=/data/arachnode.db \
    PYTHONUNBUFFERED=1

USER arachnode
EXPOSE 8000

# Seed is idempotent (upsert on policy id), so it's safe to run on
# every container start — it only ever brings the DB up to date with
# the current policy library, never wipes decisions or quarantine
# history.
CMD python seed.py && exec gunicorn -w 2 -b 0.0.0.0:8000 --access-logfile - wsgi:app

