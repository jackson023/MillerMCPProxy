"""auth_db.py -- key cutover: the gateway asks db-v3 whether a key from platform_api_keys may pass (api_key op=authorize).

The old check (_key_match against the Secret Manager keys) runs first and is unchanged. This module is asked only when
that check said no AND the caller presented something shaped like a platform key (miq_ + 43 url-safe characters), so a
garbage or empty credential never costs a database call.

What leaves the gateway is the sha256 of the key and the scope, never the key. db-v3 answers accept=true only when
platform_settings.auth_db_keys_mode is 'enforce', so the whole cutover is one setting and the undo is flipping it back.

Fail-safe in both directions: any error, timeout or odd answer is accept=false, so the old verdict stands (never a new
lock-out, never a new opening). Answers are cached for TTL_S seconds, so a revoke or an expiry reaches the gateway
within that window; an error is remembered for ERR_TTL_S so a down database is not hammered.

Standard library only. Never raises into the caller. Never logs or stores the presented key.
"""
import asyncio
import hashlib
import logging
import re
import time

logger = logging.getLogger("miller.gateway.auth_db")

KEY_PREFIX = "miq_"
KEY_LEN = 47
TTL_S = 30.0
ERR_TTL_S = 5.0
TIMEOUT_S = 3.0
MAX_ENTRIES = 1024
_SCOPES = ("mcp", "execute", "admin")
_KEY_BODY = re.compile(r"^[A-Za-z0-9_-]+$")

_cache: dict = {}
_sender = {"fn": None}
_stats = {"asked": 0, "cached": 0, "accepted": 0, "errors": 0}


def configure(sender):
    """sender: async fn(key_sha256, scope) -> the api_key tool result (or the gateway's {'result': ...} wrapper)."""
    _sender["fn"] = sender


def _now():
    return time.monotonic()


def looks_like_key(presented):
    return (
        isinstance(presented, str)
        and len(presented) == KEY_LEN
        and presented.startswith(KEY_PREFIX)
        and bool(_KEY_BODY.match(presented))
    )


def fingerprint(presented):
    return hashlib.sha256(presented.encode("utf-8")).hexdigest()


def _remember(ck, ok, ttl):
    if len(_cache) >= MAX_ENTRIES:
        now = _now()
        for k in [k for k, v in _cache.items() if v[0] <= now]:
            del _cache[k]
        if len(_cache) >= MAX_ENTRIES:
            _cache.clear()
    _cache[ck] = (_now() + ttl, ok)


async def accepts(presented, scope):
    """True only when db-v3 says this key may pass this scope right now. Never raises."""
    try:
        if _sender["fn"] is None or scope not in _SCOPES or not looks_like_key(presented):
            return False
        ck = (fingerprint(presented), scope)
        hit = _cache.get(ck)
        if hit is not None and hit[0] > _now():
            _stats["cached"] += 1
            return hit[1]
        _stats["asked"] += 1
        try:
            res = await asyncio.wait_for(_sender["fn"](ck[0], scope), timeout=TIMEOUT_S)
        except Exception as exc:
            _stats["errors"] += 1
            _remember(ck, False, ERR_TTL_S)
            logger.warning("auth_db authorize failed: %s", type(exc).__name__)
            return False
        inner = res.get("result", res) if isinstance(res, dict) else None
        if not isinstance(inner, dict) or inner.get("status") != "ok":
            _stats["errors"] += 1
            _remember(ck, False, ERR_TTL_S)
            return False
        ok = inner.get("accept") is True
        _remember(ck, ok, TTL_S)
        if ok:
            _stats["accepted"] += 1
        return ok
    except Exception as exc:
        logger.warning("auth_db accepts failed: %s", type(exc).__name__)
        return False


def stats():
    return dict(_stats, cached_entries=len(_cache))
