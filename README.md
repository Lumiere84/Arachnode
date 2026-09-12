# Arachnode AI — Policy Engine

A Flask service that evaluates access / threat / data-governance events
against a signed policy library, records every decision in a
hash-linked audit chain, and gates any *loosening* of enforcement
behind a human-held Discernment Key — plus the console UI, served by
this same service, so there is exactly one Arachnode AI, not a demo
and a backend that happen to agree with each other.

(A separate, fully self-contained HTML file — no backend, no server —
also exists for sharing the concept with people who won't run this
project: same look, but its "engine" is a JS mirror running in the
browser. This one is the real thing.)

## Quickstart

```bash
pip install -r requirements.txt
python seed.py          # loads the 7-policy library into arachnode.db
python run.py            # starts the dev server on :5000
```

Open **http://127.0.0.1:5000/** — that's the console, served by Flask
itself and talking to its own API over plain relative fetches
(`/events`, `/policies`, …). Same origin, so there's no CORS to
configure and nothing for a browser's cross-origin rules to block.

No other services or accounts are required — storage is a local
sqlite3 file, and Flask is the only third-party dependency.

The console will ask your browser to log in the first time you open
it (username `admin`, password `dev-admin-password-change-me` out of
the box) — that's the front door, described below. Same credentials
work for curl (`-u admin:...`) against every other endpoint.

Set real secrets before running this anywhere but your own machine —
the app prints a warning at startup for any of these still on its
documented default:

```bash
export ARACHNODE_SIGNING_SECRET="<long random string, held by the service>"
export ARACHNODE_DISCERNMENT_KEY="<a different string, held by a human approver>"
export ARACHNODE_ADMIN_USER="<a real username>"
export ARACHNODE_ADMIN_PASSWORD="<a real password, different from the two above>"
```

## Two different locks

**The front door (`app/auth.py`).** HTTP Basic Auth in front of the
entire app — the console included, since a page that shows your policy
library and lets you fire events is exactly as sensitive as the API it
calls. `/health` is the one exception, so an uptime checker doesn't
need credentials. This is deliberately simple: one shared operator
credential (`ARACHNODE_ADMIN_USER`/`ARACHNODE_ADMIN_PASSWORD`), checked
with `hmac.compare_digest` so a guess can't be timed. Basic Auth rather
than a custom token because browsers handle it natively — one login
prompt on the console's first load, and the browser then attaches the
same credentials to every same-origin `fetch()` the console makes
afterwards. No token to bake into the page. Swap this for real
per-user auth (SSO, an identity provider) once more than a handful of
people share this login.

**The Discernment Key, inside that door.** Logging in as the operator
and a human deliberately approving one specific loosening action are
different guarantees — so a second, separate secret gates those.

## The security model, in one paragraph

Every policy is HMAC-signed with a secret only the service holds. A
write that goes through the signed paths (`POST`/`PATCH`/`DELETE
/policies`) re-signs the policy, so the engine keeps trusting and
enforcing it. A write that bypasses the API — a compromised process
with raw database access, simulated here by `POST /admin/rogue-edit/:id`
— changes a policy's behavior without updating its signature, and
`evaluate()` catches the mismatch on the next event, ignores that
policy, and raises a SECURITY ALERT block in the audit chain instead
of quietly enforcing the tampered rule. Signing proves a write came
from the service. It does not prove a human approved it — so anything
that *loosens* enforcement requires a second, separate secret: the
Discernment Key, supplied via the `X-Discernment-Key` header. That
covers four specific operations, not just one:

| Operation | Loosens when | Needs the key when |
|---|---|---|
| `PATCH /policies/:id` | setting `action` to `allow`, or re-enabling a disabled policy | that condition holds |
| `POST /policies` | the new policy is enabled **and** its action is `allow` | always for such a policy |
| `DELETE /policies/:id` | the policy being removed is a deny/quarantine/capture rule | always for those (deleting an `allow` rule tightens, and needs no key) |
| `POST /quarantine/:id/release` | always | always |

The engine can tighten enforcement — and change its own rule set —
entirely on its own; only a human can loosen it. Every create, update,
and delete on `/policies` is also written to the audit chain as a
`policy_change` block, so the rule set's own history is exactly as
auditable as the decisions it produces.

## API

Every path here needs the Basic Auth login (`/health` is the one
exception) *on top of* whatever the "Notes" column says.

| Method | Path                          | Notes |
|---|---|---|
| GET  | `/health`                        | liveness check |
| GET  | `/policies?domain=`              | list policies, optionally filtered |
| POST | `/policies`                      | create; enabled `allow` policies need the Discernment Key |
| PATCH| `/policies/<id>`                 | signed edit path; `action:"allow"` needs the Discernment Key |
| DELETE| `/policies/<id>`                | deleting anything but an `allow` rule needs the Discernment Key |
| POST | `/events`                        | `{"domain": "...", "payload": {...}}` → runs `evaluate()` |
| GET  | `/audit-chain`                   | the full hash-linked block list |
| POST | `/audit-chain/verify`            | recomputes hashes, reports the first broken block if any |
| GET  | `/quarantine`                    | contained items |
| POST | `/quarantine/<id>/release`       | needs the Discernment Key |
| POST | `/admin/rogue-edit/<id>`         | demo-only; 404s unless `DEBUG=True` |
| POST | `/admin/corrupt-block/<idx>`     | demo-only; rewrites a block's content without touching its hash, so `/audit-chain/verify` has something real to catch |

Every path below except `/health` needs `-u admin:<password>` (or
whatever `ARACHNODE_ADMIN_USER`/`_PASSWORD` are set to) — omitted from
the examples for brevity, but curl will get a 401 without it:

```bash
# Fire the same "agent requests admin scope" scenario the console's
# Scenario Console runs, and see the decision trace:
curl -u admin:dev-admin-password-change-me \
  -X POST localhost:5000/events -H 'Content-Type: application/json' -d '{
  "domain": "threat",
  "payload": {"agent": {"requested_scope": "admin", "granted_scope": "read_only"}}
}'

# Add a new restriction — tightens, no Discernment Key needed:
curl -u admin:dev-admin-password-change-me \
  -X POST localhost:5000/policies -H 'Content-Type: application/json' -d '{
  "id": "p-no-interns", "name": "Deny interns everywhere",
  "domain": "access", "priority": 1, "action": "deny",
  "conditions": [{"field": "actor.role", "operator": "eq", "value": "intern"}]
}'

# Remove a restriction — loosens, needs the Discernment Key too:
curl -u admin:dev-admin-password-change-me \
  -X DELETE localhost:5000/policies/p-no-interns \
  -H "X-Discernment-Key: $ARACHNODE_DISCERNMENT_KEY"
```

## Project layout

```
app/
  crypto.py    canonical JSON, HMAC policy signing, audit-chain hashing
  engine.py    evaluate() — pure function, no I/O, fully unit-testable
  db.py        sqlite3 data access (no ORM dependency)
  routes.py    the Flask blueprint above
  __init__.py  app factory; also serves webui/index.html at "/"
webui/
  index.html   the console — same origin as the API, calls it directly
seed.py        the 7-policy library, identical to the console demo
tests/
  test_engine.py   unit tests: the console's 8 demo scenarios + tamper cases
  test_api.py      end-to-end tests through the real Flask API
```

## Tests

```bash
python -m unittest discover -s tests -v
```

29 tests: the 8 scenarios the console's Scenario Console advertises,
tamper-detection (rogue edit is caught and skipped), signed-edit
trust, audit-chain rewrite detection, all four Discernment Key gates,
policy create/delete (validation, conflict handling, the tighten/loosen
distinction in both directions, and that a deleted policy actually
stops firing), and the Basic Auth front door (no credentials, wrong
credentials, right credentials, `/health` staying open). All pass
against the actual engine and API — not a mock.

## Deployment

```bash
cp .env.example .env      # fill in real values — all four, not just the two secrets
docker compose up --build
```

That runs the same app under `gunicorn` instead of Flask's dev server
(`wsgi.py` → `wsgi:app`), with `debug=False` — so the `/admin/rogue-edit`
and `/admin/corrupt-block` demo-only endpoints are inert (404) there,
exactly like they are outside `DEBUG` anywhere else. The sqlite file
lives on a named Docker volume (`arachnode-data`), so decisions,
quarantine history, and policy edits survive a container restart;
without that volume every restart starts from a freshly reseeded DB.

**Basic Auth is a floor, not a ceiling.** It stops a random port scan
or drive-by script from reaching the API at all, and it's real
authentication, not theater — but it's one shared credential with no
lockout, no audit trail of *who* logged in (only what they did once
in), and no MFA. Fine for a small team; put a real reverse proxy or
identity provider in front before this is reachable by more than a
handful of trusted people, and don't publish port 8000 directly to the
internet regardless.

I haven't been able to actually build or run this image in the sandbox
I built it in (no Docker daemon available there) — the `Dockerfile`,
`wsgi.py` import, and `gunicorn` command are all correct against a
verified-working app, but do a `docker compose up --build` smoke test
on your end before relying on it.

## What's deliberately out of scope for this MVP

- Per-user accounts, lockout after failed attempts, and MFA — see
  "Deployment" above; the built-in Basic Auth is one shared credential,
  which is a floor, not the ceiling this needs at real scale.
- Multi-writer concurrency control on the audit chain (sqlite3's
  default locking is fine for a demo; a production deployment would
  want a real append-only log or a database with proper isolation).
- Pagination on `/policies`, `/audit-chain`, `/quarantine` — fine at
  demo volume, worth adding once a real deployment has real history.
- A "create policy" form in the console UI — the API supports it
  (`POST /policies`, see above); the console currently only exposes
  Delete, since a full policy-authoring form (conditions, operators,
  domain/priority pickers) is a meaningfully bigger UI job than the
  rest of this update.
