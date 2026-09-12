"""
The front door. HTTP Basic Auth in front of the entire app — the
console included, since a console that shows your policy library and
lets you fire events is exactly as sensitive as the API it calls.

This is deliberately the *simplest* thing that actually works, not the
most sophisticated:

- A single shared operator credential (ARACHNODE_ADMIN_USER /
  ARACHNODE_ADMIN_PASSWORD), compared with hmac.compare_digest so a
  wrong guess can't be timed byte-by-byte. Good enough for "one team
  running one console"; swap for real per-user auth (SSO, an identity
  provider) before this has more than a handful of operators who
  shouldn't share a login.
- HTTP Basic rather than a custom token scheme because browsers handle
  it natively: the first request to "/" prompts the browser's own
  login dialog, and the browser then attaches the same credentials to
  every same-origin fetch() the console makes afterwards — no token to
  bake into the page, no login form to build.
- /health stays open, so an uptime checker doesn't need credentials
  just to ask "are you alive".

This is the front door, not the whole house: it stops an
unauthenticated caller from reaching the API at all. The Discernment
Key (see app/routes.py) is a second, different lock on two specific
actions *inside* that door — loosening enforcement — because "logged
in as the operator" and "a human just deliberately approved this one
loosening action" are not the same guarantee.
"""
import hmac
import sys

from flask import Response, current_app, request

EXEMPT_PATHS = {"/health"}


def _credentials_ok(auth) -> bool:
    if auth is None:
        return False
    user_ok = hmac.compare_digest(auth.username or "", current_app.config["ADMIN_USER"])
    pass_ok = hmac.compare_digest(auth.password or "", current_app.config["ADMIN_PASSWORD"])
    return user_ok and pass_ok


def install_auth(app):
    @app.before_request
    def _require_basic_auth():
        if request.path in EXEMPT_PATHS:
            return None
        if _credentials_ok(request.authorization):
            return None
        return Response(
            "Authentication required.", 401,
            {"WWW-Authenticate": 'Basic realm="Arachnode AI Policy Engine"'},
        )


def warn_if_using_dev_defaults(app):
    """Not a security control — just a loud reminder at startup, since
    a secret left on its documented default is not a secret."""
    if app.config.get("TESTING"):
        return
    import os
    for env_var, default in app.config.get("DEV_DEFAULTS", {}).items():
        if os.environ.get(env_var, default) == default:
            print(
                f"[arachnode] WARNING: {env_var} is using its dev default. "
                "Set a real value before running this anywhere but your own machine.",
                file=sys.stderr,
            )
