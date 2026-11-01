"""
Miller MCP Gateway v3.0 — Stateless Proxy

Architecture change from v2.0:
  v2.0: Gateway had its own asyncpg pool + exec() engine. Any AlloyDB issue
        killed meta_tool calls even when miller-mcp-db-v3 was healthy.
  v3.0: Zero database connections. Pure HTTP proxy to miller-mcp-db-v3/execute.
        AlloyDB failover, SmartPool degraded mode, and BigQuery fallback all
        happen inside db-v3 — the gateway is fully transparent to all of it.

Components:
  CircuitBreaker  — 5 consecutive 5xx/timeout → open 30s → half-open probe
  _proxy()        — authenticated httpx POST to db-v3 /execute
  ping            — local handler, always available regardless of db-v3 state
  gateway_status  — local handler, probes db-v3 /health, returns full state
  tools/list      — served from static definitions, zero I/O on MCP handshake
  /health         — local, reports gateway + circuit state, never queries AlloyDB
  /execute        — REST passthrough, proxies to db-v3 /execute
"""

# ==============================================================================
# server.py -- miller-mcp-gateway  |  NAVIGATION INDEX
# grep: "# == § " to list all section headers  |  679 lines
# ==============================================================================
# § 001  Imports
# § 002  Logging
# § 003  Config (DB_V3_URL, API_KEY, GW_VERSION)
# § 004  UUID Discovery -- header scan for Claude conversation UUID auto-wiring
# § 005  Circuit Breaker (5 failures -> open 30s -> half-open probe)
# § 006  Static Bootstrap Tools (meta_tool, ping, gateway_status -- zero I/O)
# § 007  Local Tool Handlers (ping, gateway_status -- never leave container)
# § 008  Proxy (_proxy -> db-v3 /execute, circuit-breaker wrapped)
# § 009  FastAPI App + Startup probe
# § 010  JSON-RPC Helpers (_sanitize_json_escapes, _ok, _err)
# § 011  MCP Method Handlers (_handle_initialize, tools/list, tools/call)
# § 012  Routes (/mcp POST, /mcp GET, /execute passthrough, /health)
# ==============================================================================
import asyncio
import datetime
import hmac
import json
import logging
import os
import re as _re
import time
import uuid
from contextvars import ContextVar as _ContextVar
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

# == § 002  LOGGING ===========================================================
# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("miller-mcp-gateway")

# == § 003  CONFIG =============================================================
# DB_V3_URL: primary service URL (irj2rlhsea variant for Jidoka intercept).
# API_KEY: required, set via Cloud Run env var -- no hardcoded fallback.
# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DB_V3_URL     = os.environ.get("DB_V3_URL", "https://miller-mcp-db-v3-irj2rlhsea-uc.a.run.app")
DB_V3_EXECUTE = f"{DB_V3_URL}/execute"
DB_V3_HEALTH  = f"{DB_V3_URL}/health"
API_KEY       = os.environ.get("API_KEY", "")  # Required — set via Cloud Run env var. No hardcoded fallback.
# Bug 52545: dual-key acceptance. API_KEY_SECONDARY is any additional accepted key (the incoming
# key before a swap, the outgoing key after it). It is accepted but never sent upstream.
# The sentinel "unset" (or anything shorter than _MIN_KEY_LEN) means no rotation window is open.
API_KEY_SECONDARY = os.environ.get("API_KEY_SECONDARY", "")
# /mcp auth mode: off = no check (legacy), warn = check and record unauthenticated callers on the
# bus but allow them, enforce = 401. Any other value fails safe to warn, never silently to off.
MCP_AUTH_MODE = os.environ.get("MCP_AUTH_MODE", "warn").strip().lower()
if MCP_AUTH_MODE not in ("off", "warn", "enforce"):
    logger.warning("MCP_AUTH_MODE=%r is not off|warn|enforce; using warn", MCP_AUTH_MODE)
    MCP_AUTH_MODE = "warn"
GW_VERSION          = "3.2.0"

# S1409: Last-known session_key for context telemetry.
# Tools like platform_search don't carry session_key in arguments.
# When any tool call DOES include session_key, we store it here.
# Subsequent calls without session_key use it as fallback.
# Single-user gateway -- one active session at a time.
_last_known_sk: str = ""
_bg_tasks: set = set()  # retained refs for fire-and-forget asyncio tasks -- an
# unreferenced task is GC-eligible under Cloud Run CPU throttling before it
# ever runs (sTR #17/#55-A pattern); .discard on completion keeps this bounded.
GCLOUD_RUNNER_URL   = os.environ.get("GCLOUD_RUNNER_URL", "https://miller-gcloud-runner-146372550543.us-central1.run.app")
GCLOUD_RUNNER_EXEC  = f"{GCLOUD_RUNNER_URL}/execute"

# == § 003a  WORK TICKETS ([decision] #51749) ===================================
# The gateway is the door every Claude tool call comes through. A work ticket (the trace id) is minted here for each
# request (_WorkTicketDoor, outermost), carried to our services as a W3C traceparent, and every outbound call is
# counted as a compute grant (one enforcement point: httpx.AsyncClient.send, process-wide). The gateway has no
# database: counts are flushed once a minute through db-v3 /execute -> work_ticket_ingest (runtime 'gateway').
import work_ticket as _work_ticket  # noqa: E402

_work_ticket.RUNTIME = "gateway"
_gw_ticket: _ContextVar[dict] = _ContextVar("_gw_ticket", default={})
_WT_IN_FLUSH: _ContextVar[bool] = _ContextVar("_WT_IN_FLUSH", default=False)   # the books themselves are not work
_work_ticket.set_reader(lambda: (_gw_ticket.get() or {}).get("trace_id"))
_W3C_TP_RE = _re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")
_HEX32_RE = _re.compile(r"^(?!0{32})[0-9a-f]{32}$")
_HEX16_RE = _re.compile(r"^(?!0{16})[0-9a-f]{16}$")


def _wt_new() -> dict:
    return {"trace_id": os.urandom(16).hex(), "span_id": os.urandom(8).hex(), "parent_span_id": None}


def _wt_trace_id() -> str:
    """The current request's ticket (32 hex). Every place that used to mint its own uuid4 uses this instead."""
    return (_gw_ticket.get() or {}).get("trace_id") or os.urandom(16).hex()


def _wt_ticket_from_headers(headers, path: str) -> dict:
    """X-Trace-Id (32 hex or a UUID) or a valid traceparent from one of OUR callers is inherited; otherwise mint.
    On /mcp the inbound traceparent is Anthropic's per-turn trace (kept as _anthropic_trace_id by tools/call),
    never our ticket: each MCP request gets its own."""
    if not path.startswith("/mcp"):
        _x = (headers.get("x-trace-id") or "").strip().lower().replace("-", "")
        if _HEX32_RE.match(_x):
            return {"trace_id": _x, "span_id": os.urandom(8).hex(), "parent_span_id": None}
        _m = _W3C_TP_RE.match((headers.get("traceparent") or "").strip().lower())
        if _m and _HEX32_RE.match(_m.group(1)):
            # the door is its own span, a child of the caller's. Cloud Run rewrites the traceparent parent-id on
            # every hop, so the caller's real span travels in X-Miller-Span (set by our own services).
            _xs = (headers.get("x-miller-span") or "").strip().lower()
            return {"trace_id": _m.group(1), "span_id": os.urandom(8).hex(),
                    "parent_span_id": _xs if _HEX16_RE.match(_xs) else _m.group(2)}
    return _wt_new()


# == § 003c  TRACE TO LINE OF CODE ([bug] #64738) ================================
# A gateway failure must be one platform_trace_timeline(id=<trace_id>) call from the exact file, function and line
# that raised it. culprit.py is the canonical module (the same file in every Python runtime); it reads the LIVE
# traceback, so nothing is parsed from text. The repo identity is (MillerMCPProxy, GIT_COMMIT_SHA): the commit is baked
# into the revision by cloudbuild.yaml (service.yaml env, COMMIT_SHA_PLACEHOLDER) and is None, never guessed, when it
# is not. The lines come from /app/server.py in the image, which IS the commit that was built.
# The gateway has no database, so a record rides the span flush to db-v3 (gateway_span_ingest 'errors'), which writes
# the platform_error_bus row (source_file/line/function + context.culprit) under the request's trace_id.
# Three ways in: (1) _TlLogHandler: every WARNING/ERROR the gateway logs from inside an except block (the swallowed
# failures); (2) the door (_WorkTicketDoor): an exception no route caught; (3) _tl_error() called directly.
import culprit as _culprit  # noqa: E402

_TL_IDENTITY = _culprit.build_identity("MillerMCPProxy")
# [bug] #64738 line level: which of the gateway's OWN lines ran for each request (the gateway runs no tool code). The door
# span carries them as attributes.lines_ran, keyed by path under the app directory; with attributes.build (repo@commit12)
# that names the exact source: platform_trace_timeline code_ran.builds[].lines_ran shows it with a link to the file at that commit.
import line_trace as _line_trace  # noqa: E402
_line_trace.add_repo_root(os.path.dirname(os.path.abspath(__file__)))
_line_trace.enable()
_TL_ROOTS = [os.path.dirname(os.path.abspath(__file__))]
_TL_ERRORS: list = []
_TL_ERRORS_MAX = 200
_TL_FLUSH_MAX = 50
_TL_SEEN: dict = {}
_TL_DEDUPE_S = 60.0


def _tl_error(exc, where: str) -> None:
    """Queue the culprit record for one failure. Never raises: capture must not break the path it describes.
    The same failure site seen again inside one trace (or, with no request, inside 60s) is recorded once."""
    try:
        if exc is None:
            return
        _t = _gw_ticket.get() or {}
        _tid = _t.get("trace_id") if _HEX32_RE.match(str(_t.get("trace_id") or "")) else None
        # who asked: the platform's caller label for a request (mcp / direct_api_key), None for the gateway's own
        # background work. platform_error_bus_monitor counts only the None (production) rows toward its alerts.
        _caller = _wt_caller(_t["path"], None) if _tid and _t.get("path") and _t.get("entry") != "boot" else None
        _cul = _culprit.culprit_from_exc(exc, _TL_ROOTS, _TL_IDENTITY)
        _key = (_tid, _cul.get("file"), _cul.get("line"), _cul.get("error_class"))
        _now = time.monotonic()
        _last = _TL_SEEN.get(_key)
        if _last is not None and _now - _last < _TL_DEDUPE_S:
            return
        if len(_TL_SEEN) > 500:
            _TL_SEEN.clear()
        _TL_SEEN[_key] = _now
        if len(_TL_ERRORS) >= _TL_ERRORS_MAX:
            del _TL_ERRORS[0]
        _TL_ERRORS.append({
            "trace_id": _tid or os.urandom(16).hex(), "span_id": _t.get("span_id"), "tool": _t.get("tool"),
            "caller": _caller, "where": str(where)[:120], "error_name": type(exc).__name__[:80], "error_msg": str(exc)[:500],
            "culprit": _cul})
    except Exception:
        pass


class _TlLogHandler(logging.Handler):
    """A WARNING or ERROR logged from inside an except block is a failure the gateway swallowed: take its culprit
    from the exception being handled (logging runs this synchronously, in the same context as the log call)."""

    def emit(self, record) -> None:
        try:
            _ei = record.exc_info
            _exc = _ei[1] if isinstance(_ei, tuple) and len(_ei) > 1 and _ei[1] is not None else _culprit.current_exc()
            if _exc is not None:
                _tl_error(_exc, "log:%s:%s" % (record.name, record.funcName))
        except Exception:
            pass


_tl_handler = _TlLogHandler(level=logging.WARNING)
for _tl_logger_name in ("miller-mcp-gateway", "smart_pool", "work_ticket"):
    logging.getLogger(_tl_logger_name).addHandler(_tl_handler)


# -- Spans: the gateway leg of every trace (platform_trace_timeline) ----------------------------------------------
# One span per request at the door and one per outbound call, so a trace reads Claude -> gateway -> db-v3 -> ... as
# one tree. Each outbound hand-off is its own span: its id goes out as the traceparent parent-id AND as X-Miller-Span
# (Cloud Run rewrites the traceparent parent-id on every hop; db-v3's door reads X-Miller-Span). Spans are buffered
# (bounded, oldest dropped and counted) and sent every few seconds through db-v3 /execute -> gateway_span_ingest.
_WT_SPANS: list = []
_WT_SPANS_MAX = 5000
_WT_SPAN_BATCH = 500
_WT_SPAN_EVERY_S = 5.0
_WT_SPANS_DROPPED = [0]
_WT_SPAN_SKIP_PATHS = frozenset({"/health"})          # liveness probes are not work
_WT_TOOL_RE = _re.compile(rb'"tool_name"\s*:\s*"([A-Za-z0-9_.:\-]{1,120})"')


def _wt_iso(epoch_s: float) -> str:
    return datetime.datetime.fromtimestamp(epoch_s, datetime.timezone.utc).isoformat(timespec="milliseconds")


def _wt_span_add(span: dict) -> None:
    if len(_WT_SPANS) >= _WT_SPANS_MAX:
        del _WT_SPANS[0]
        _WT_SPANS_DROPPED[0] += 1
    _WT_SPANS.append(span)


def _wt_caller(path: str, status) -> str:
    """The caller label for the gateway's spans: the MCP door is 'mcp'; the key-guarded REST routes are
    'direct_api_key' (db-v3 uses the same label for key auth); a request the auth gate refused stays 'unattributed'."""
    if status == 401:
        return "unattributed"
    return "mcp" if path.startswith("/mcp") else "direct_api_key"


def _wt_dest(host: str) -> str:
    if host.startswith("miller-mcp-db-v3"):
        return "db-v3"
    if host.startswith("miller-gcloud-runner"):
        return "gcloud-runner"
    if host.endswith(".run.app"):
        return host.split(".")[0][:60]
    return host[:60] or "unknown"


def _wt_label(tool_name: str | None = None, rpc: str | None = None) -> None:
    """Name what this request is doing (the JSON-RPC method, the real tool after meta_tool unwrap) on its door span."""
    _t = _gw_ticket.get()
    if isinstance(_t, dict):
        if tool_name and not _t.get("tool"):
            _t["tool"] = str(tool_name)[:120]
        if rpc and not _t.get("rpc"):
            _t["rpc"] = str(rpc)[:60]


class _WorkTicketDoor:
    """Pure ASGI, outermost: every HTTP request gets its ticket before any route code runs, and its door span."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        _tok = None
        _ticket = None
        _lt_rec = _line_trace.begin()   # never raises; None = this request runs untraced
        _t0 = time.time()
        _m0 = time.monotonic()
        _status = [None]
        _exc_name = [None]
        try:
            _hdrs = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or ()}
            _ticket = _wt_ticket_from_headers(_hdrs, scope.get("path") or "")
            _ticket["path"] = (scope.get("path") or "")[:200]
            _tok = _gw_ticket.set(_ticket)
        except Exception:
            _tok = None

        async def _send(message):
            if message.get("type") == "http.response.start":
                _status[0] = message.get("status")
            await send(message)

        try:
            return await self.app(scope, receive, _send)
        except BaseException as _exc:
            # [bug] #64738: an exception no route caught. The ticket is still set here, so the record is under
            # this request's trace_id. Cancellation is not a failure.
            _exc_name[0] = type(_exc).__name__
            if isinstance(_exc, Exception):
                _tl_error(_exc, "door:%s" % (scope.get("path") or "")[:100])
            raise
        finally:
            if _tok is not None:
                _gw_ticket.reset(_tok)
            _lt_sum = _line_trace.end(_lt_rec)
            try:
                _path = scope.get("path") or ""
                if _ticket and scope.get("type") == "http" and _path not in _WT_SPAN_SKIP_PATHS:
                    _code = _status[0]
                    _op = f"{scope.get('method') or 'GET'} {_path}"[:100]
                    if _ticket.get("rpc"):
                        _op = f"{_op} {_ticket['rpc']}"
                    _wt_span_add({
                        "trace_id": _ticket["trace_id"], "span_id": _ticket["span_id"],
                        "parent_span_id": _ticket.get("parent_span_id"), "service": "gateway",
                        "operation": _op, "tool": _ticket.get("tool"),
                        "status": "ok" if _code is not None and _code < 400 and not _exc_name[0] else "error",
                        "caller_source": _wt_caller(_path, _code),
                        "start": _wt_iso(_t0), "end": _wt_iso(_t0 + (time.monotonic() - _m0)),
                        "attrs": {"path": _path[:200], "http_status": _code if _code is not None else 0,
                                  **({"rpc": _ticket["rpc"]} if _ticket.get("rpc") else {}),
                                  **({"error": _exc_name[0]} if _exc_name[0] else {}),
                                  **_line_trace.span_attributes(_lt_sum)},
                    })
            except Exception:
                pass


_ORIG_HTTPX_SEND = httpx.AsyncClient.send


async def _wt_send(self, request, *args, **kwargs):
    """Every outbound request is a compute grant and a span; hand-offs to our own services carry the ticket as
    traceparent + X-Miller-Span (the hand-off's own span id)."""
    _rec = None
    try:
        if not _WT_IN_FLUSH.get():
            _h = (request.url.host or "").lower()
            _gp = _work_ticket.http_point(_h, request.url.path)
            if _gp:
                _work_ticket.grant(_gp, lambda: f"host:{_h}")
            _t = _gw_ticket.get() or {}
            if _gp and _HEX32_RE.match(str(_t.get("trace_id") or "")):
                _cs = os.urandom(8).hex()
                if _h.endswith(".run.app") and "traceparent" not in request.headers:
                    request.headers["traceparent"] = f"00-{_t['trace_id']}-{_cs}-01"
                    request.headers["x-miller-span"] = _cs
                _tool = None
                if _h.endswith(".run.app"):
                    try:
                        _tm = _WT_TOOL_RE.search(bytes(request.content[:2048]))
                        _tool = _tm.group(1).decode("ascii") if _tm else None
                    except Exception:
                        _tool = None            # a streamed body is not read here
                _rec = {"trace_id": _t["trace_id"], "span_id": _cs, "parent_span_id": _t.get("span_id"),
                        "dest": _wt_dest(_h), "host": _h, "path": request.url.path, "method": request.method,
                        "tool": _tool, "t0": time.time(), "m0": time.monotonic(),
                        "caller": "boot" if _t.get("entry") == "boot" else _wt_caller(_t.get("path") or "", None)}
    except Exception:
        _rec = None
    _code = None
    _err = None
    try:
        _resp = await _ORIG_HTTPX_SEND(self, request, *args, **kwargs)
        _code = _resp.status_code
        return _resp
    except BaseException as exc:
        _err = type(exc).__name__
        raise
    finally:
        if _rec is not None:
            try:
                _wt_span_add({
                    "trace_id": _rec["trace_id"], "span_id": _rec["span_id"],
                    "parent_span_id": _rec["parent_span_id"], "service": _rec["dest"],
                    "operation": f"{_rec['method']} {_rec['path']}"[:120], "tool": _rec["tool"],
                    "status": "ok" if _code is not None and _code < 400 else "error",
                    "caller_source": _rec["caller"],
                    "start": _wt_iso(_rec["t0"]), "end": _wt_iso(_rec["t0"] + (time.monotonic() - _rec["m0"])),
                    "attrs": {"url_host": _rec["host"][:200], "url_path": str(_rec["path"])[:200],
                              "method": _rec["method"], "http_status": _code or 0,
                              **({"error": _err} if _err else {})},
                })
            except Exception:
                pass


httpx.AsyncClient.send = _wt_send


async def _wt_write(minute, runtime, points, sites, totals, misses) -> None:
    """flush_with writer: the gateway's counts go to platform_work_ticket_grants through db-v3."""
    payload = {"tool_name": "work_ticket_ingest", "arguments": {
        "minute": minute.isoformat(), "runtime": runtime, "points": points, "sites": sites,
        "totals": totals, "misses": misses}}
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=3.0)) as client:
        r = await client.post(DB_V3_EXECUTE, json=payload, headers={"X-API-Key": API_KEY,
                                                                    "Content-Type": "application/json"})
    if r.status_code != 200:
        raise RuntimeError(f"work_ticket_ingest HTTP {r.status_code}")
    _body = r.json()
    _inner = _body.get("result", _body) if isinstance(_body, dict) else {}
    if (isinstance(_body, dict) and _body.get("status") == "error") or \
            (isinstance(_inner, dict) and _inner.get("status") == "error"):
        raise RuntimeError(f"work_ticket_ingest refused: {str(_body)[:200]}")


async def _wt_flush_loop() -> None:
    _WT_IN_FLUSH.set(True)   # this task only: its own posts are the books, not work
    await _work_ticket.flush_loop_with(_wt_write)


# [decision] #51749 which code ran: the gateway's own build rides every span batch (gateway_span_ingest stamps it on each
# span as attributes.build, the key db-v3 stamps on its spans), so platform_trace_timeline meta.code_ran lists the gateway
# build beside db-v3's. repo@commit12 from the baked GIT_COMMIT_SHA; None, never guessed, when the image has none.
_WT_BUILD12 = ("MillerMCPProxy@" + _TL_IDENTITY["commit"][:12]) if len(_TL_IDENTITY.get("commit") or "") >= 12 else None


async def _wt_span_write(spans: list, errors: list | None = None) -> None:
    """Send one batch of spans, and the failures with their culprit ([bug] #64738), to db-v3 (gateway_span_ingest).
    Raises on any failure so the caller keeps them."""
    _args = {"spans": spans}
    if _WT_BUILD12:
        _args["build"] = _WT_BUILD12
    if errors:
        _args["errors"] = errors
    payload = {"tool_name": "gateway_span_ingest", "arguments": _args}
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=3.0)) as client:
        r = await client.post(DB_V3_EXECUTE, json=payload, headers={"X-API-Key": API_KEY,
                                                                    "Content-Type": "application/json"})
    if r.status_code != 200:
        raise RuntimeError(f"gateway_span_ingest HTTP {r.status_code}")
    _body = r.json()
    _inner = _body.get("result", _body) if isinstance(_body, dict) else {}
    if (isinstance(_body, dict) and _body.get("status") == "error") or \
            (isinstance(_inner, dict) and _inner.get("status") == "error"):
        raise RuntimeError(f"gateway_span_ingest refused: {str(_body)[:200]}")
    if isinstance(_inner, dict) and _inner.get("rejected"):
        logger.warning("gateway_span_ingest rejected %s span(s): %s", _inner.get("rejected"), _inner.get("rejects"))
    if isinstance(_inner, dict) and _inner.get("errors_rejected"):
        logger.warning("gateway_span_ingest rejected %s error record(s): %s", _inner.get("errors_rejected"),
                       _inner.get("error_rejects"))


async def _wt_span_flush() -> int:
    """Send everything buffered, one batch at a time. A failed batch goes back to the front of the buffer (still
    bounded by _WT_SPANS_MAX / _TL_ERRORS_MAX), so a db-v3 blip loses nothing that fits."""
    sent = 0
    while _WT_SPANS or _TL_ERRORS:
        batch = _WT_SPANS[:_WT_SPAN_BATCH]
        del _WT_SPANS[:len(batch)]
        errs = _TL_ERRORS[:_TL_FLUSH_MAX]
        del _TL_ERRORS[:len(errs)]
        try:
            await _wt_span_write(batch, errs)
        except Exception as exc:
            _WT_SPANS[:0] = batch[: max(0, _WT_SPANS_MAX - len(_WT_SPANS))]
            _TL_ERRORS[:0] = errs[: max(0, _TL_ERRORS_MAX - len(_TL_ERRORS))]
            logger.warning("gateway span flush failed (%d kept for next flush): %r", len(batch), exc)
            break
        sent += len(batch)
    if _WT_SPANS_DROPPED[0]:
        logger.warning("gateway span buffer full: %d oldest span(s) dropped", _WT_SPANS_DROPPED[0])
        _WT_SPANS_DROPPED[0] = 0
    return sent


async def _wt_span_loop() -> None:
    _WT_IN_FLUSH.set(True)   # this task only: sending the spans is not itself work to record
    while True:
        await asyncio.sleep(_WT_SPAN_EVERY_S)
        try:
            await _wt_span_flush()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("gateway span loop: %r", exc)

# == § 003b  KEY AUTH (Bug 52545: dual-key acceptance + /mcp gate) ================
# One enforcement point for every key-guarded route (/execute, /admin/*, /mcp).
#   _key_match(presented)  -> "current" | "secondary" | ""   (constant-time, fails closed)
#   _auth_gate(request, route, ...) -> True when the request may proceed
# Every secondary/invalid/absent-key request leaves a bus row (log_audit_event), deduped per
# caller signature per hour, so "who still uses the old key" is a query, not a guess.
# The presented key is never logged or stored.
_MIN_KEY_LEN = 16
_AUTH_EVENT_TTL_S = 3600
_auth_events_seen: dict = {}
if len(API_KEY) < _MIN_KEY_LEN:
    logger.error("API_KEY missing or shorter than %d chars -- key-guarded routes will fail closed", _MIN_KEY_LEN)


def _key_match(presented: str) -> str:
    if not presented:
        return ""
    p = presented.encode("utf-8", "ignore")
    matched = ""
    # No early exit: every candidate is compared, each in constant time.
    for label, key in (("current", API_KEY), ("secondary", API_KEY_SECONDARY)):
        if len(key) >= _MIN_KEY_LEN and hmac.compare_digest(p, key.encode("utf-8")):
            matched = matched or label
    return matched


def _presented_key(request: Request, allow_query: bool = False) -> str:
    key = request.headers.get("x-api-key", "")
    if not key:
        auth = request.headers.get("authorization", "")
        if auth[:7].lower() == "bearer ":
            key = auth[7:].strip()
    if not key and allow_query:
        key = request.query_params.get("api_key", "")
    return key


async def _emit_auth_event(event_type: str, data: dict) -> None:
    # platform_audit_log.entity_id is an integer column, so the gateway's identity travels in data.
    payload = {"event_type": event_type, "entity_type": "gateway_auth",
               "data": dict(data, gateway="miller-mcp-gateway")}
    try:
        res = await _proxy("log_audit_event", payload, _wt_trace_id())
    except Exception as exc:  # the bus write must never break or block the request
        logger.warning("auth_event_write_failed type=%s err=%s", event_type, exc)
        return
    # log_audit_event reports a rejected insert as {"status": "error"} inside an HTTP 200 -- never swallow it.
    inner = res.get("result", res) if isinstance(res, dict) else {}
    if not isinstance(inner, dict) or inner.get("status") != "ok":
        logger.error("auth_event_write_rejected type=%s result=%.300s", event_type, res)


def _record_auth_event(request: Request, route: str, state: str, mode: str) -> None:
    ua = request.headers.get("user-agent", "")[:120]
    origin = request.headers.get("origin", "")[:120]
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()[:64]
    sig = f"{route}|{state}|{ua}|{origin}|{ip}"
    now = time.monotonic()
    last = _auth_events_seen.get(sig)
    if last is not None and now - last < _AUTH_EVENT_TTL_S:
        return
    if len(_auth_events_seen) > 512:
        _auth_events_seen.clear()
    _auth_events_seen[sig] = now
    logger.warning("gateway_auth route=%s state=%s mode=%s ua=%r origin=%r ip=%s", route, state, mode, ua, origin, ip)
    task = asyncio.create_task(_emit_auth_event(
        "gateway_auth_" + state,
        {"route": route, "state": state, "mode": mode, "user_agent": ua,
         "origin": origin, "ip": ip, "gateway_version": GW_VERSION},
    ))
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)


def _auth_gate(request: Request, route: str, *, allow_query: bool = False, mode: str = "enforce") -> bool:
    presented = _presented_key(request, allow_query)
    matched = _key_match(presented)
    if matched != "current":
        _record_auth_event(request, route, matched or ("invalid" if presented else "absent"), mode)
    return bool(matched) or mode != "enforce"

# == § 004  UUID DISCOVERY =====================================================
# _extract_uuid_from_headers: scans incoming MCP headers for Claude UUID.
# Priority: explicit conversation ID headers -> Referer URL -> full scan.
# Used by Tier 0 auto-injection in open_session (zero client required).
# _upstream_hdrs ContextVar: captures ALL headers per MCP call for forwarding.
# ---------------------------------------------------------------------------
# Enterprise header capture — UUID auto-discovery across all client types
# (Claude native app, iPhone Safari, desktop browser, Claude Code)
# ---------------------------------------------------------------------------
_UUID_PATTERN = _re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    _re.I,
)
_upstream_hdrs: _ContextVar[dict] = _ContextVar('_upstream_hdrs', default={})
_FORWARD_PREFIXES = (
    'anthropic-', 'x-claude-', 'x-conversation-', 'x-chat-',
    'referer', 'origin', 'traceparent', 'baggage',
)


def _extract_uuid_from_headers(hdrs: dict) -> str | None:
    """Scan incoming MCP request headers for a Claude conversation UUID.

    Priority order: explicit conversation ID headers → Referer URL UUID.
    Falls back to full-header scan, skipping auth/generated headers.
    Returns lowercase UUID string or None.
    """
    priority_keys = [
        'x-conversation-id', 'anthropic-conversation-id',
        'x-claude-conversation-id', 'x-claude-chat-uuid',
        'x-chat-id', 'referer',
    ]
    for k in priority_keys:
        v = hdrs.get(k) or hdrs.get(k.lower())
        if v:
            m = _UUID_PATTERN.search(str(v))
            if m:
                return m.group(0).lower()
    # Full-header scan — skip tokens we generated or standard auth headers
    _skip = ('x-api-key', 'authorization', 'x-trace-id', 'x-gateway-version',
             'content-', 'accept', 'host')
    for k, v in hdrs.items():
        if any(k.lower().startswith(s) for s in _skip):
            continue
        if v and isinstance(v, str):
            m = _UUID_PATTERN.search(v)
            if m:
                return m.group(0).lower()
    return None


# == § 005  CIRCUIT BREAKER ====================================================
# Three states: closed (normal) -> open (5 consecutive 5xx/timeout) -> half-open.
# open: fail fast, no calls to db-v3. half-open after 30s: one probe allowed.
# Auth failures (401) do NOT penalize the circuit -- config problem, not health.
# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------
class CircuitBreaker:
    """
    Three-state circuit breaker wrapping all db-v3 proxy calls.

    closed    → normal operation
    open      → db-v3 considered down, calls fail fast with a clean error
    half-open → one probe allowed after recovery_s seconds
    """

    def __init__(self, threshold: int = 5, recovery_s: float = 30.0, breaker_name: str = "db_v3_proxy") -> None:
        self.threshold    = threshold
        self.recovery_s   = recovery_s
        self.breaker_name = breaker_name
        self._failures:  int          = 0
        self._opened_at: float | None = None
        self._state:     str          = "closed"

    def record_success(self) -> None:
        _was_open = self._state != "closed"
        if _was_open:
            logger.info(
                "circuit_breaker CLOSED — db-v3 recovered after %d failures",
                self._failures,
            )
        self._failures  = 0
        self._opened_at = None
        self._state     = "closed"
        if _was_open:
            _schedule_persist(self)

    def record_failure(self) -> None:
        self._failures += 1
        _opened = False
        if self._failures >= self.threshold and self._state == "closed":
            self._state     = "open"
            self._opened_at = time.monotonic()
            _opened = True
            logger.error(
                "circuit_breaker OPENED after %d consecutive failures — db-v3 considered down",
                self._failures,
            )
        elif self._state == "half-open":
            self._state     = "open"
            self._opened_at = time.monotonic()
            _opened = True
            logger.error("circuit_breaker half-open probe FAILED — reopening")
        if _opened:
            _schedule_persist(self)

    def allow_request(self) -> bool:
        if self._state == "closed":
            return True
        if self._state == "open":
            if self._opened_at and (time.monotonic() - self._opened_at) >= self.recovery_s:
                self._state = "half-open"
                logger.info("circuit_breaker HALF-OPEN — allowing probe")
                return True
            return False
        return True  # half-open: allow one probe through

    @property
    def state(self) -> str:
        return self._state

    @property
    def failures(self) -> int:
        return self._failures

    def to_dict(self) -> dict:
        seconds_until_retry: float | None = None
        if self._state == "open" and self._opened_at:
            remaining = self.recovery_s - (time.monotonic() - self._opened_at)
            seconds_until_retry = max(0.0, round(remaining, 1))
        return {
            "state":               self._state,
            "failures":            self._failures,
            "threshold":           self.threshold,
            "recovery_s":          self.recovery_s,
            "seconds_until_retry": seconds_until_retry,
        }


# == § 005b  CIRCUIT BREAKER PERSISTENCE (decision #33575 lineage, Task 4) ====
# Best-effort, fire-and-forget persistence through db-v3's gateway_circuit_state
# tool -- the gateway never touches AlloyDB directly (single-service-touches-DB
# architecture). Only fires on state TRANSITIONS (open/close), never on every
# request, and never awaited inline -- cannot add latency or a new failure mode
# to the hot path this breaker exists to protect.
# ---------------------------------------------------------------------------
_PROCESS_START_MONOTONIC = time.monotonic()
_PROCESS_START_WALL      = time.time()


def _monotonic_to_wall_iso(mono_ts: float | None) -> str | None:
    if mono_ts is None:
        return None
    from datetime import datetime, timezone
    wall = _PROCESS_START_WALL + (mono_ts - _PROCESS_START_MONOTONIC)
    return datetime.fromtimestamp(wall, tz=timezone.utc).isoformat()


async def _persist_circuit_state(breaker: "CircuitBreaker") -> None:
    """Fire-and-forget persistence of a circuit breaker state transition.
    Swallows all errors -- persistence failing must never affect proxy behavior.
    """
    try:
        payload = {
            "tool_name": "gateway_circuit_state",
            "arguments": {
                "action":       "set",
                "breaker_name": breaker.breaker_name,
                "state":        breaker.state,
                "failures":     breaker.failures,
                "threshold":    breaker.threshold,
                "recovery_s":   breaker.recovery_s,
                "opened_at":    _monotonic_to_wall_iso(breaker._opened_at),
            },
        }
        headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0, connect=2.0)) as client:
            await client.post(DB_V3_EXECUTE, json=payload, headers=headers)
    except Exception as exc:
        logger.warning("circuit_breaker persist failed (non-fatal): %s", exc)


def _schedule_persist(breaker: "CircuitBreaker") -> None:
    """Schedule persistence as a background task -- never awaited inline."""
    try:
        asyncio.create_task(_persist_circuit_state(breaker))
    except RuntimeError:
        pass  # no running event loop yet -- nothing to persist at import time


_circuit = CircuitBreaker()

# == § 006  STATIC BOOTSTRAP TOOLS ============================================
# Served from tools/list with zero I/O -- no DB, no network, no latency.
# Only 3 tools registered at the MCP layer: meta_tool, ping, gateway_status.
# meta_tool routes all 1,954 platform tools via single unwrapping dispatch.
# ---------------------------------------------------------------------------
# Static bootstrap tool definitions
# Served from tools/list with zero I/O — no DB, no network, no latency.
# ---------------------------------------------------------------------------
_BOOTSTRAP_TOOLS = [
    {
        "name": "meta_tool",
        "description": (
            "Universal dispatcher — executes any tool in the Miller IQ platform registry by name. "
            "Pass tool_name and arguments. All 1,700+ platform tools are reachable via this single entry point. "
            "| updated v2: handle arguments arriving as JSON string (MCP serialization) vs dict — both paths safe"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {
                    "type": "string",
                    "description": "Name of the tool to execute",
                },
                "arguments": {
                    "type": "object",
                    "description": "Arguments to pass to the tool",
                    "default": {},
                },
            },
            "required": ["tool_name"],
        },
    },
    {
        "name": "ping",
        "description": (
            "Gateway liveness check. Returns pong. "
            "Handled locally — always available regardless of db-v3 or AlloyDB state."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "gateway_status",
        "description": (
            "Live gateway health: circuit breaker state, db-v3 reachability, version. "
            "Handled locally — probes db-v3 /health and returns full diagnostic state."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "restart_service",
        "description": (
            "Emergency restart for a Cloud Run service via miller-gcloud-runner. "
            "Gateway-local — never touches db-v3, always available even when db-v3 is blocked. "
            "Use when db-v3 is frozen and meta_tool calls are timing out. "
            "Allowed: miller-mcp-db-v3, miller-playwright-mcp, miller-gcloud-runner."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Cloud Run service name to restart (default: miller-mcp-db-v3)",
                    "default": "miller-mcp-db-v3",
                },
            },
        },
    },
]

# == § 007  LOCAL TOOL HANDLERS ================================================
# ping and gateway_status are handled entirely inside the gateway container.
# gateway_status probes db-v3 /health and returns full diagnostic state.
# ---------------------------------------------------------------------------
# Local tool handlers — never leave the gateway container
# ---------------------------------------------------------------------------
async def _handle_ping(_args: dict) -> dict:
    return {
        "status":  "pong",
        "service": "miller-mcp-gateway",
        "version": GW_VERSION,
        "mode":    "stateless-proxy",
    }


async def _probe_dispatch() -> dict:
    """Gate 3 (2026-10-21 db-v3 lockup): one REAL tool call through db-v3 /execute.

    db-v3 /health answered in ~45ms during the lockup while every tool call hung for
    120s, because /health never touches _dispatch or the connection pool. This posts
    dispatch_health_probe (auth + _dispatch + tool load + pool checkout + SELECT 1)
    with an 8s budget. A timeout here is the same failure class _proxy already counts,
    so it is recorded on the circuit breaker; success is NOT recorded, so a passing
    probe can never mask real tool failures by resetting the failure count.
    """
    t0 = time.monotonic()
    out: dict = {"tool": "dispatch_health_probe", "status": "unknown"}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=3.0)) as client:
            r = await client.post(
                DB_V3_EXECUTE,
                json={"tool_name": "dispatch_health_probe", "arguments": {"budget_ms": 3000}},
                headers={"X-API-Key": API_KEY, "X-Gateway-Version": GW_VERSION,
                         "Content-Type": "application/json"},
            )
        out["latency_ms"] = round((time.monotonic() - t0) * 1000)
        if r.status_code != 200:
            out["status"] = f"http_{r.status_code}"
            return out
        body = r.json() if r.content else {}
        res = body.get("result", body) if isinstance(body, dict) else {}
        if not isinstance(res, dict):
            res = {}
        out["status"] = res.get("status", "unknown")
        for _k in ("acquire_ms", "query_ms", "total_ms", "error"):
            if res.get(_k) is not None:
                out[_k] = res[_k]
    except httpx.TimeoutException:
        out["latency_ms"] = round((time.monotonic() - t0) * 1000)
        out["status"] = "timeout"
        _circuit.record_failure()
    except Exception as exc:
        out["latency_ms"] = round((time.monotonic() - t0) * 1000)
        out["status"] = f"error:{type(exc).__name__}"
    return out


async def _handle_gateway_status(_args: dict) -> dict:
    """Probes db-v3 /health AND a real tool dispatch; reports the truth.

    overall is 'healthy' only when /health is up AND the dispatch probe returns ok.
    'degraded' = dispatch works but slowly. 'down' = dispatch fails or times out
    (the 2026-10-21 shape: /health green, tools hanging).
    """
    db_v3_status              = "unknown"
    db_v3_tools: int | None   = None
    db_v3_latency_ms: int | None = None
    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            r = await client.get(DB_V3_HEALTH, headers={"X-API-Key": API_KEY})
        db_v3_latency_ms = round((time.monotonic() - t0) * 1000)
        if r.status_code == 200:
            body = r.json()
            db_v3_status = body.get("status", "healthy")
            db_v3_tools  = body.get("tools_loaded")
        else:
            db_v3_status = f"http_{r.status_code}"
    except httpx.TimeoutException:
        db_v3_latency_ms = round((time.monotonic() - t0) * 1000)
        db_v3_status = "timeout"
    except Exception as exc:
        db_v3_latency_ms = round((time.monotonic() - t0) * 1000)
        db_v3_status = f"error:{type(exc).__name__}"
    dispatch = await _probe_dispatch()
    _health_up = db_v3_status in ("ok", "healthy")
    if _health_up and dispatch.get("status") == "ok":
        overall = "healthy"
    elif _health_up and dispatch.get("status") == "degraded":
        overall = "degraded"
    else:
        overall = "down"
    return {
        "overall": overall,
        "gateway": {
            "version": GW_VERSION,
            "status":  "healthy",
            "mode":    "stateless-proxy",
        },
        "circuit_breaker": _circuit.to_dict(),
        "db_v3": {
            "url":          DB_V3_URL,
            "status":       db_v3_status,
            "tools_loaded": db_v3_tools,
            "latency_ms":   db_v3_latency_ms,
            "dispatch":     dispatch,
        },
    }


# Services permitted to be restarted via the watchdog endpoint.
# Explicit allowlist -- never allow arbitrary service names.
_RESTARTABLE_SERVICES = {"miller-mcp-db-v3", "miller-playwright-mcp", "miller-gcloud-runner"}


async def _handle_restart_service(args: dict) -> dict:
    """
    Restart a Cloud Run service via miller-gcloud-runner.
    Gateway-local -- no db-v3 in the call chain, always reachable.
    Injects RESTART_TS env var to force a new revision without code changes.
    """
    service = (args.get("service") or "miller-mcp-db-v3").strip()
    if service not in _RESTARTABLE_SERVICES:
        return {
            "status": "error",
            "error": f"'{service}' not in restart allowlist: {sorted(_RESTARTABLE_SERVICES)}",
        }
    ts = int(time.time())
    command = (
        f"gcloud run services update {service}"
        f" --update-env-vars=RESTART_TS={ts}"
        f" --region=us-central1"
        f" --project=miller-iq-platform"
    )
    logger.info("restart_service initiating service=%s ts=%d", service, ts)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(90.0, connect=5.0)) as client:
            r = await client.post(
                f"{GCLOUD_RUNNER_URL}/run",
                # S1461: /run directly -- /execute->run_gcloud->/run was unauthenticated double-hop
                json={"command": command, "timeout": 75, "session_key": _last_known_sk},
                headers={
                    # S1461 v2: Bearer JWT auth (HS256, aud=miller-gcloud-runner).
                    # gcloud-runner jwt_loaded=true confirmed. Replaces broken TOTP path.
                    "Authorization": "Bearer " + __import__("jwt").encode(
                        {
                            "aud": "miller-gcloud-runner",
                            "iat": int(__import__("time").time()),
                            "exp": int(__import__("time").time()) + 120,
                        },
                        os.environ.get("RUNNER_JWT_SECRET", ""),
                        algorithm="HS256",
                    ),
                    "Content-Type": "application/json",
                },
            )
        if r.status_code == 200:
            logger.info("restart_service OK service=%s", service)
            return {"status": "ok", "service": service, "initiated": True, "result": r.json()}
        logger.error("restart_service FAILED service=%s http=%d body=%.300s", service, r.status_code, r.text)
        return {"status": "error", "service": service, "http_code": r.status_code, "detail": r.text[:500]}
    except Exception as exc:
        logger.error("restart_service ERROR service=%s err=%s", service, exc)
        return {"status": "error", "service": service, "error": str(exc)}


# @zero_usage_confirmed -- server.py is a GitHub infra file, not a tool_registry entry
# S1503: gateway auto-stage interceptor -- eliminates Pattern B for code_edit callers
async def _handle_code_edit(arguments: dict) -> Any:
    """Gateway interceptor: auto-stage string params in code_edit calls.

    Eliminates Pattern B. Any plain string in params.find / params.end_find /
    params.new_src is staged automatically via stage_payload before the call
    reaches db-v3. Claude passes plain strings -- no escaping, no pre-staging,
    no Pattern B ritual. Fail-open: staging failure passes raw string through.

    Handles: single-op (params={}), batch-ops (ops=[...]).
    Pass-through: tools_ops=, tools='all' (complex batch, handled in db-v3).
    """
    _trace = _wt_trace_id()   # [decision] #51749: the request's ticket, not a fresh id
    session_key = (arguments or {}).get("session_key", "")
    args = dict(arguments or {})
    _STAGE_FIELDS = ("find", "end_find", "new_src")

    async def _auto_stage_params(params: dict) -> dict:
        if not isinstance(params, dict):
            return params
        out = dict(params)
        for field in _STAGE_FIELDS:
            val = params.get(field)
            if val and isinstance(val, str) and not params.get(f"{field}_staged_id"):
                try:
                    stage_res = await _proxy("stage_payload", {
                        "payload": val,
                        "payload_type": "html",
                        "session_key": session_key,
                    }, _trace)
                    sid = (stage_res or {}).get("result", {}).get("staged_id")
                    if sid:
                        out.pop(field)
                        out[f"{field}_staged_id"] = sid
                except Exception as _e:
                    logger.warning(
                        "code_edit auto-stage FAILED field=%s err=%s -- passing raw",
                        field, _e,
                    )
        return out

    if "params" in args and isinstance(args.get("params"), dict):
        args["params"] = await _auto_stage_params(args["params"])

    if "ops" in args and isinstance(args.get("ops"), list):
        staged_ops = []
        for op_item in args["ops"]:
            if isinstance(op_item, dict) and isinstance(op_item.get("params"), dict):
                op_item = dict(op_item)
                op_item["params"] = await _auto_stage_params(op_item["params"])
            staged_ops.append(op_item)
        args["ops"] = staged_ops

    return await _proxy("code_edit", args, _trace)


def _canary_trace_to_line(mode: str) -> None:
    """Fails on purpose, at one known line. The canary asserts that the trace names THIS function and THIS line."""
    raise RuntimeError("gateway trace-to-line canary: " + mode)  # CANARY_GATEWAY_RAISE_LINE


async def _canary_bad_writer(*_a) -> None:
    """The counts writer of the wt_flush canary: fails on purpose, at one known line, like an unreachable db-v3."""
    raise ConnectionError("gateway work_ticket flush canary: ingest unreachable")  # CANARY_GATEWAY_WT_FLUSH_LINE


def _canary_upstream() -> None:
    """Stands in for a db-v3 failure so the /execute 502 path can be fired live. _proxy calls it for the one tool name
    gateway_canary_upstream, before the circuit breaker is touched (a canary must not count against db-v3's health)."""
    raise RuntimeError("gateway upstream canary: simulated db-v3 failure")  # CANARY_GATEWAY_UPSTREAM_LINE


async def _canary_wt_flush() -> dict:
    """Fire the work_ticket flush-failure path live: one counts row is seeded, flush_with hands it to a writer that
    raises, flush_with logs the failure from inside its except block (the _TlLogHandler records it) and puts the counts
    back. The seeded row is removed afterwards, so nothing is written to the grants table and no real count is lost."""
    _k = ("gateway_canary", "gateway_canary_trace")
    with _work_ticket._lock:
        _work_ticket._counts.setdefault(_k, [0, 0])[0] += 1
    try:
        _n = await _work_ticket.flush_with(_canary_bad_writer)
    finally:
        with _work_ticket._lock:
            _work_ticket._counts.pop(_k, None)
    return {"status": "ok", "mode": "wt_flush", "flushed": _n, "trace_id": _wt_trace_id(),
            "commit": _TL_IDENTITY.get("commit"),
            "expect": {"file": "server.py", "function": "_canary_bad_writer", "line_marker": "CANARY_GATEWAY_WT_FLUSH_LINE"}}


async def _canary_self_call(mode: str) -> dict:
    """Fire the door path (door) or the /execute 502 path (upstream502) through the REAL app, in process: the request goes
    through _WorkTicketDoor and the real route with the gateway's own key, and inherits this call's trace id.
      door        -> POST /execute with a JSON array body: rest_execute raises on body.get, no route catches it, the door
                     records it (where=door:/execute) and the client sees a 500.
      upstream502 -> POST /execute for tool gateway_canary_upstream: _proxy raises, rest_execute answers 502 and records it."""
    _t = _gw_ticket.get() or {}
    _tid = _t.get("trace_id") or _wt_trace_id()
    _hdrs = {"X-API-Key": API_KEY, "Content-Type": "application/json",
             "traceparent": "00-%s-%s-01" % (_tid, os.urandom(8).hex())}
    if _HEX16_RE.match(str(_t.get("span_id") or "")):
        _hdrs["x-miller-span"] = _t["span_id"]
    _body = "[]" if mode == "door" else json.dumps({"tool_name": "gateway_canary_upstream", "arguments": {}})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                                 base_url="http://gateway.canary", timeout=httpx.Timeout(10.0)) as _c:
        _r = await _c.post("/execute", content=_body, headers=_hdrs)
    _exp = ({"file": "server.py", "function": "rest_execute", "line_marker": "tool_name = body.get(", "where": "door:/execute"}
            if mode == "door" else
            {"file": "server.py", "function": "_canary_upstream", "line_marker": "CANARY_GATEWAY_UPSTREAM_LINE", "where": "rest_execute"})
    return {"status": "ok", "mode": mode, "http_status": _r.status_code, "trace_id": _tid,
            "commit": _TL_IDENTITY.get("commit"), "expect": _exp}


async def _handle_canary_trace(args: dict) -> dict:
    """[bug] #64738 standing canary for the gateway runtime. meta_tool(tool_name='gateway_canary_trace',
    arguments={'mode': 'raise' | 'swallow' | 'wt_flush' | 'door' | 'upstream502'}); the last three fire the work_ticket flush
    failure, the door (uncaught exception) path and the /execute 502 path live, see _canary_wt_flush / _canary_self_call.
      raise   -> the failure escapes this handler, as a real handler failure would: _handle_tools_call catches it.
      swallow -> the failure is logged and the call carries on, as the gateway's best-effort paths do.
    Either way ONE platform_trace_timeline(id=<trace_id>) must show meta.culprit = server.py, _canary_trace_to_line,
    the CANARY_GATEWAY_RAISE_LINE line, this build's commit, and ~5 source lines around it."""
    mode = str((args or {}).get("mode") or "raise")
    if mode not in ("raise", "swallow", "wt_flush", "door", "upstream502"):
        return {"status": "error", "error": "mode must be raise, swallow, wt_flush, door or upstream502", "got": mode[:40]}
    if mode == "wt_flush":
        return await _canary_wt_flush()
    if mode in ("door", "upstream502"):
        return await _canary_self_call(mode)
    if mode == "raise":
        _canary_trace_to_line(mode)
    try:
        _canary_trace_to_line(mode)
    except Exception as exc:
        logger.warning("gateway canary swallowed failure: %r", exc)
    return {"status": "ok", "mode": mode, "trace_id": _wt_trace_id(), "commit": _TL_IDENTITY.get("commit"),
            "expect": {"file": "server.py", "function": "_canary_trace_to_line", "line_marker": "CANARY_GATEWAY_RAISE_LINE"}}


_LOCAL_HANDLERS: dict[str, Any] = {
    "ping":            _handle_ping,
    "gateway_status":  _handle_gateway_status,
    "restart_service": _handle_restart_service,
    "code_edit":       _handle_code_edit,
    "gateway_canary_trace": _handle_canary_trace,
}

# == § 008  PROXY (_proxy) =====================================================
# Every non-local tool call proxies to db-v3 /execute via _proxy().
# Circuit breaker wraps every call. 120s timeout (5s connect).
# Auth failure (401) -> config error, not circuit penalized.
# 5xx/timeout -> circuit failure recorded, potential OPEN state.
# ---------------------------------------------------------------------------
# Proxy — forward tool call to db-v3 /execute
# ---------------------------------------------------------------------------
async def _proxy(tool_name: str, arguments: dict, trace_id: str) -> Any:
    """
    Forward a tool call to miller-mcp-db-v3 /execute.
    Circuit breaker wraps every call. Structured audit log on every outcome.
    """
    if not _circuit.allow_request():
        cb = _circuit.to_dict()
        raise RuntimeError(
            f"Gateway circuit breaker OPEN — db-v3 unavailable. "
            f"Retry in {cb['seconds_until_retry']}s. "
            f"Consecutive failures: {cb['failures']}/{cb['threshold']}."
        )

    if tool_name == "gateway_canary_upstream":   # [bug] #64738: the live canary for the /execute 502 path
        _canary_upstream()

    payload = {"tool_name": tool_name, "arguments": arguments or {}}
    headers = {
        "X-API-Key":         API_KEY,
        "X-Trace-Id":        trace_id,
        "X-Gateway-Version": GW_VERSION,
        "Content-Type":      "application/json",
    }
    # ── Forward upstream headers to db-v3 for tool-level observability ────
    # anthropic-*, x-claude-*, x-conversation-*, referer, origin forwarded
    # as X-Upstream-{Header} — enables future tool-level UUID extraction.
    for _k, _v in _upstream_hdrs.get().items():
        if any(_k.lower().startswith(_p) for _p in _FORWARD_PREFIXES):
            _fwd_key = f'X-Upstream-{_k.replace("-", " ").title().replace(" ", "-")}'
            headers[_fwd_key] = str(_v)[:500]

    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=5.0)) as client:
            r = await client.post(DB_V3_EXECUTE, json=payload, headers=headers)

        elapsed_ms = int((time.monotonic() - t0) * 1000)

        if r.status_code == 401:
            # Auth failure is a config problem, not a db-v3 health problem — do not penalize circuit
            logger.error("proxy_auth_failure tool=%s trace=%s", tool_name, trace_id)
            raise RuntimeError(
                "Gateway→db-v3 authentication failed. Check API_KEY configuration."
            )

        if r.status_code >= 500:
            _circuit.record_failure()
            logger.error(
                "proxy_error tool=%s http=%d elapsed_ms=%d trace=%s body=%.300s",
                tool_name, r.status_code, elapsed_ms, trace_id, r.text,
            )
            raise RuntimeError(f"db-v3 returned HTTP {r.status_code}")

        _circuit.record_success()
        logger.info(
            "proxy_ok tool=%s http=%d elapsed_ms=%d trace=%s",
            tool_name, r.status_code, elapsed_ms, trace_id,
        )
        return r.json()

    except httpx.TimeoutException as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        _circuit.record_failure()
        logger.error(
            "proxy_timeout tool=%s elapsed_ms=%d failures=%d trace=%s",
            tool_name, elapsed_ms, _circuit.failures, trace_id,
        )
        raise RuntimeError(
            f"db-v3 timeout after {elapsed_ms}ms "
            f"(circuit failures: {_circuit.failures}/{_circuit.threshold})"
        ) from exc

    except httpx.RequestError as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        _circuit.record_failure()
        logger.error(
            "proxy_unreachable tool=%s elapsed_ms=%d failures=%d trace=%s err=%s",
            tool_name, elapsed_ms, _circuit.failures, trace_id, exc,
        )
        raise RuntimeError(f"db-v3 unreachable: {exc}") from exc


# == § 009  FASTAPI APP + STARTUP ==============================================
# Startup probe: non-circuit-breaker check of db-v3 /health at boot.
# Logs reachability but does NOT affect circuit state on failure.
# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="Miller MCP Gateway", version=GW_VERSION, docs_url=None, redoc_url=None)
app.add_middleware(_WorkTicketDoor)   # [decision] #51749: outermost -- the ticket exists before any route runs


@app.on_event("startup")
async def _startup() -> None:
    # [decision] #51749: boot is an entry point (startup probes, circuit seeding); then start the minute flusher.
    _gw_ticket.set({**_wt_new(), "entry": "boot"})
    _wt_task = asyncio.create_task(_wt_flush_loop())
    _bg_tasks.add(_wt_task)
    _wt_task.add_done_callback(_bg_tasks.discard)
    _wt_span_task = asyncio.create_task(_wt_span_loop())
    _bg_tasks.add(_wt_span_task)
    _wt_span_task.add_done_callback(_bg_tasks.discard)
    logger.info(
        "Miller MCP Gateway v%s — stateless proxy mode. db-v3: %s",
        GW_VERSION, DB_V3_URL,
    )
    # Non-circuit-breaker startup probe — logs db-v3 reachability, does not affect circuit state
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            r = await client.get(DB_V3_HEALTH, headers={"X-API-Key": API_KEY})
        logger.info("Startup probe → db-v3 HTTP %d", r.status_code)
    except Exception as exc:
        logger.warning("Startup probe → db-v3 unreachable (non-fatal): %s", exc)

    # Seed circuit breaker state from last persisted state (decision #33575
    # lineage, Task 4). Best-effort, fail-open on any error -- same posture as
    # the reachability probe above. Prevents a fresh deploy from serving full
    # traffic straight into an ongoing db-v3 outage, and prevents it staying
    # falsely OPEN forever after a real recovery that happened while this
    # instance was down.
    try:
        from datetime import datetime
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            r = await client.post(
                DB_V3_EXECUTE,
                json={
                    "tool_name": "gateway_circuit_state",
                    "arguments": {"action": "get", "breaker_name": _circuit.breaker_name},
                },
                headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
            )
        if r.status_code == 200:
            _persisted = (r.json() or {}).get("result", {})
            if _persisted.get("found") and _persisted.get("state") == "open" and _persisted.get("opened_at"):
                _opened_wall = datetime.fromisoformat(_persisted["opened_at"]).timestamp()
                _elapsed = time.time() - _opened_wall
                if _elapsed < _circuit.recovery_s:
                    _circuit._state     = "open"
                    _circuit._failures  = _persisted.get("failures", _circuit.threshold)
                    _circuit._opened_at = time.monotonic() - _elapsed
                    logger.warning(
                        "Startup: seeded circuit breaker OPEN from persisted state "
                        "(%.1fs into %.1fs recovery window)", _elapsed, _circuit.recovery_s,
                    )
                else:
                    _circuit._state     = "half-open"
                    _circuit._opened_at = time.monotonic() - _circuit.recovery_s
                    logger.info(
                        "Startup: seeded circuit breaker HALF-OPEN "
                        "(persisted open state past recovery window)"
                    )
        logger.info("Startup: circuit breaker state seed complete — state=%s", _circuit.state)
    except Exception as exc:
        logger.warning("Startup: circuit breaker state seed failed (non-fatal, defaulting closed): %s", exc)


# == § 010  JSON-RPC HELPERS ===================================================
# _sanitize_json_escapes: strips invalid escapes (e.g. \' from Python patches)
# before json.loads -- eliminates 'inner arguments JSON parse failed' errors.
# S1171: enterprise fix for Claude-constructed patch strings.
# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------
def _sanitize_json_escapes(s: str) -> str:
    """Strip invalid JSON escape sequences before json.loads/raw_decode.

    JSON only allows: \\\", \\\\, \\/, \\b, \\f, \\n, \\r, \\t, \\uXXXX.
    Python-style \\' (and any other \\X where X is not a valid JSON escape)
    causes json.loads to throw. Strip the backslash — \\' becomes ', which
    is the intent. This is safe: single quotes never need escaping in JSON.

    S1171: enterprise fix — eliminates the 'meta_tool: inner arguments JSON
    parse failed' failure mode that occurred when Claude constructed patch
    strings with Python-style quoting.
    """
    import re as _re_sj
    # Strip \ not followed by a valid JSON escape char
    return _re_sj.sub(r'\\(?!["\\\'/bfnrtu0-9])', '', s)


def _ok(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}

def _err(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


# S1220: proactive block for oversized inline string arguments -- meta_tool's JSON
# argument transport does not reliably ERROR on large payloads, it can silently
# CORRUPT them instead (the sanitizer above strips backslashes it should not),
# so a payload that happens to parse at this size still cannot be trusted.
# Blocking above a safe threshold, before ever attempting json.loads, is the
# only trustworthy behavior. platform_publish has a matching *_gcs_url sibling
# for every content-heavy parameter -- that is the correct, reliable path.
_LARGE_PAYLOAD_THRESHOLD = 3000  # chars, raw string length before any parsing


def _large_payload_block(req_id: Any, raw_len: int, tool_name: str) -> dict:
    return _ok(req_id, {
        "content": [{"type": "text", "text": json.dumps({
            "error": "BLOCKED: payload too large for meta_tool's inline JSON argument transport.",
            "size_chars": raw_len,
            "threshold_chars": _LARGE_PAYLOAD_THRESHOLD,
            "tool": tool_name,
            "fix": (
                "Do not retry with base64, manual re-escaping, or any other inline workaround -- "
                "this transport is unreliable above the threshold regardless of encoding. Instead: "
                "(1) write the content to a file with bash_tool; "
                "(2) upload it via curl -X POST https://miller-mcp-db-v3-146372550543.us-central1.run.app/platform/upload "
                "-H 'X-API-Key: <key>' -H 'X-Upload-Filename: <name>' -H 'X-Upload-Folder: <folder>' --data-binary @file; "
                "(3) pass the matching *_gcs_url parameter to platform_publish instead of the inline field: "
                "code_gcs_url (for code=), js_gcs_url (for js=), sql_gcs_url (for sql=), html_gcs_url (for html=), "
                "patches_gcs_url (for patches=), yaml_gcs_url, jinja_gcs_url, shell_gcs_url. "
                "platform_publish fetches the content server-side -- the large blob never touches this transport."
            ),
        })}],
        "isError": True,
    })


# == § 011  MCP METHOD HANDLERS ================================================
# _handle_initialize: returns protocolVersion 2025-03-26 + capabilities.
# _handle_tools_list: returns _BOOTSTRAP_TOOLS static defs, zero I/O.
# _handle_tools_call: unwraps meta_tool, Tier 0 UUID inject, traceparent
#   inject, local handler dispatch or _proxy, inline image extraction.
# _handle_single: routes JSON-RPC method to correct handler.
# ---------------------------------------------------------------------------
# MCP method handlers
# ---------------------------------------------------------------------------
async def _handle_initialize(params: dict, req_id: Any) -> dict:
    return _ok(req_id, {
        "protocolVersion": "2025-03-26",
        "capabilities":    {"tools": {"listChanged": False}},
        "serverInfo":      {"name": "miller-mcp-gateway", "version": GW_VERSION},
    })


async def _handle_tools_list(params: dict, req_id: Any) -> dict:
    """Served from static in-memory definitions — zero I/O."""
    return _ok(req_id, {"tools": _BOOTSTRAP_TOOLS})


_CONTEXT_TELEMETRY_TEXT_CAP = 60_000  # chars; bounds gateway->db-v3 telemetry payload size


async def _fire_context_telemetry(sk: str, tn: str, req_text: str, resp_text: str) -> None:
    """Fire-and-forget: record REAL tiktoken counts for context budget tracking.
    S1409, upgraded S-context-estimator-2: sends truncated raw text instead of
    just byte lengths -- record_context_telemetry tokenizes server-side via
    estimate_tokens_local (single enforcement point, no second tokenizer here)
    and stores real request_tokens/response_tokens. Byte counts still sent too,
    as a permanent, cheap fallback for the rare case tokenization itself fails."""
    req_b = len(req_text.encode("utf-8", errors="ignore"))
    resp_b = len(resp_text.encode("utf-8", errors="ignore"))
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(8.0, connect=1.0)) as c:
            await c.post(DB_V3_EXECUTE, json={
                "tool_name": "record_context_telemetry",
                "arguments": {
                    "session_key": sk, "tool_name": tn,
                    "request_bytes": req_b, "response_bytes": resp_b,
                    "request_text": req_text[:_CONTEXT_TELEMETRY_TEXT_CAP],
                    "response_text": resp_text[:_CONTEXT_TELEMETRY_TEXT_CAP],
                },
            }, headers={"X-API-Key": API_KEY, "Content-Type": "application/json"})
    except Exception:
        pass  # fire-and-forget -- never block MCP response


async def _handle_tools_call(params: dict, req_id: Any) -> dict:
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {}) or {}
    trace_id  = _wt_trace_id()   # [decision] #51749: the door's ticket for this MCP request

    # arguments may arrive as a JSON string from MCP serialization
    if isinstance(arguments, str):
        _args_raw = arguments
        if len(_args_raw) > _LARGE_PAYLOAD_THRESHOLD:
            return _large_payload_block(req_id, len(_args_raw), tool_name)
        try:
            try:
                arguments = json.loads(arguments.strip())
            except Exception:
                arguments = json.loads(_sanitize_json_escapes(arguments.strip()))
        except Exception as _exc:
            logger.error(
                "meta_tool outer_args parse FAILED tool=%s len=%d err=%s preview=%.300r",
                tool_name, len(_args_raw), _exc, _args_raw,
            )
            return _ok(req_id, {
                "content": [{"type": "text", "text": json.dumps({
                    "error": f"meta_tool: arguments JSON parse failed \u2014 {_exc}",
                    "args_len": len(_args_raw),
                    "args_preview": _args_raw[:300],
                    "hint": "Use lines=N-M mode for old_str + b64: prefix for new_str. Never construct JSON strings manually with Python-style escapes.",
                })}],
                "isError": True,
            })

    # meta_tool unwrapping: Claude calls meta_tool(tool_name=X, arguments={...})
    # Unwrap so the inner tool_name routes correctly through _proxy or _LOCAL_HANDLERS.
    _unwrap_depth = 0
    while tool_name == "meta_tool" and _unwrap_depth < 5:
        _unwrap_depth += 1
        # S1226E: looped unwrap (was a single "if") -- live debug logging confirmed
        # the wire payload can carry an extra redundant meta_tool wrapping layer
        # beyond the one this handler's own schema anticipates (client-side
        # transport artifact: params.arguments == {tool_name:'meta_tool',
        # arguments:{tool_name:X, arguments:{...}}}), so a single unwrap pass left
        # tool_name=='meta_tool' with one more nested layer still inside arguments.
        # Looping (bounded, depth<5) resolves any number of wrapping layers to the
        # real target tool; malformed/cyclic input still terminates via the cap.
        # S1224: enforce meta_tool's own schema before any string parsing.
        # Root cause of a real incident: a caller passed target-tool fields
        # as flat siblings of tool_name instead of nesting them under
        # 'arguments'. That shape error used to fall through into the
        # STRING-parsing branch below and get misdiagnosed with the
        # escaping/b64 hint -- a hint for a different failure class, which
        # steered the caller toward the wrong fix. Catching it here, before
        # any parsing, means it is always named correctly.
        _expected_keys = set(["tool_name", "arguments"])
        _unexpected = set(arguments.keys()) - _expected_keys
        if _unexpected:
            _bad = sorted(_unexpected)
            logger.error("meta_tool shape_violation unexpected_keys=%s tool=%s", _bad, arguments.get("tool_name", "?"))
            _msg = "meta_tool called with unexpected top-level argument(s): " + str(_bad) + ". Nest all target-tool fields inside arguments instead of passing them as siblings of tool_name."
            return _ok(req_id, {"content": [{"type": "text", "text": json.dumps({"error": _msg, "received_top_level_keys": sorted(arguments.keys())})}], "isError": True})
        inner      = arguments.get("tool_name", "")
        inner_args = arguments.get("arguments", {}) or {}
        if isinstance(inner_args, str):
            _raw = inner_args
            if len(_raw) > _LARGE_PAYLOAD_THRESHOLD:
                return _large_payload_block(req_id, len(_raw), inner or tool_name)
            try:
                try:
                    inner_args = json.loads(inner_args.strip())
                except Exception:
                    inner_args = json.loads(_sanitize_json_escapes(inner_args.strip()))
            except Exception as _exc:
                logger.error(
                    "meta_tool inner_args parse FAILED inner_tool=%s len=%d err=%s preview=%.300r",
                    inner, len(_raw), _exc, _raw,
                )
                return _ok(req_id, {
                    "content": [{"type": "text", "text": json.dumps({
                        "error": f"meta_tool: inner arguments JSON parse failed \u2014 {_exc}",
                        "inner_tool": inner,
                        "inner_args_len": len(_raw),
                        "inner_args_preview": _raw[:300],
                        "hint": "Use lines=N-M mode for old_str (derives from source, zero encoding) + b64: prefix for new_str. Never pass JSON strings with Python-style escapes.",
                    })}],
                    "isError": True,
                })
        tool_name = inner or tool_name
        arguments = inner_args

    # [prompt-standard]#13457 fix: normalize patches/section_patches to a list.
    # Callers used to pre-serialize as a JSON string to survive the MCP transport
    # boundary -- one gateway fix eliminates that tax for every caller forever.
    # Both the meta_tool-wrapped path (inner_args just set above) and the direct
    # call path (arguments set at line ~597) converge here before Gate 35.
    if isinstance(arguments, dict):
        for _norm_field in ("patches", "section_patches"):
            _norm_val = arguments.get(_norm_field)
            if isinstance(_norm_val, str) and _norm_val.strip().startswith("["):
                try:
                    arguments[_norm_field] = json.loads(_norm_val)
                    logger.debug(
                        "patches_normalized tool=%s field=%s", tool_name, _norm_field
                    )
                except Exception:
                    pass  # malformed -- leave as-is, tool reports clearly
        # Normalize payload: Python list/dict -> JSON string.
        # stage_payload's validation gate calls json.loads(payload) -- it needs a
        # string. When Claude passes a native Python list, serialize at the gateway
        # boundary so every caller gets consistent behavior. S1504.
        _sp_payload = arguments.get("payload")
        if isinstance(_sp_payload, (list, dict)):
            arguments["payload"] = json.dumps(_sp_payload)
            logger.debug("payload_serialized tool=%s", tool_name)

    # ── Tier 0: Auto-inject conversation UUID from gateway headers ────────
    # When open_session arrives without a UUID (native app, iPhone, any client)
    # check the captured MCP request headers for a conversation UUID.
    # If found, inject it directly — session linking becomes fully automatic.
    if tool_name == "open_session" and not (arguments or {}).get("claude_chat_uuid"):
        _h_uuid = _extract_uuid_from_headers(_upstream_hdrs.get())
        if _h_uuid:
            arguments = {**(arguments or {}),
                         "claude_chat_uuid": _h_uuid,
                         "_uuid_source": "gateway_header"}
            logger.info(
                "open_session tier0_inject uuid=%s — UUID auto-wired from MCP request headers",
                _h_uuid,
            )

    # ── Inject Anthropic trace_id into all tool calls ─────────────────────
    # traceparent trace_id is stable per Claude message turn — all tool calls
    # in one response share it. Enables platform_trace_sessions chain
    # correlation in open_session: consecutive turns link to the same session
    # key purely server-side. Zero client required — any device, any client.
    _tp_val = (_upstream_hdrs.get() or {}).get('traceparent', '')
    if _tp_val:
        _tp_parts = _tp_val.split('-')
        if len(_tp_parts) >= 2 and len(_tp_parts[1]) == 32:
            arguments = {**(arguments or {}), '_anthropic_trace_id': _tp_parts[1]}
            logger.debug("trace_id_inject trace_id=%s tool=%s", _tp_parts[1], tool_name)

    # S1353: Gate 35 -- blocks inline write-path fields for write-path tools from
    # Claude Chat / agent calls. Internal server-side _dispatch() calls never reach
    # this gateway at all (in-process, no HTTP hop, no serialization boundary) so this
    # is structurally scoped to exactly the traffic that truncates at the MCP boundary.
    # Unconditional: no force=True bypass, no size threshold. One path, every time.
    # S1418: per-tool field map -- save_session's heavy field is `intelligence`, one
    # shared tuple could not express it without gating fields absent on other tools.
    # Extended on evidence of [bug]#27719: inline args arrive TRUNCATED from the
    # client. A truncated checkpoint silently loses a session's intelligence. Staging
    # leaves only a ~100-char UUID on the wire -- payload is structurally out of reach
    # of the transport failure rather than merely labelled better.
    # BYPASS (DB-as-bus, S1439/S1441 -- GCS staging is DEAD since S1441):
    #   stage_payload(payload=CONTENT, payload_type='ddl'|'sql'|'code'|'patches'|'js'|
    #                 'css'|'html', session_key=SK) -> staged_id (UUID)
    #   platform_publish(..., staged_id=STAGED_ID,
    #                    staged_field='content'|'sql'|'code'|'patches'|'js',
    #                    session_key=SK)
    # staged_id is a UUID -- Gate 35 never fires on it. No GCS. No curl. No URLs.
    # stage_payload validates at the door (AST/DDL dry-run/EXPLAIN) before storing.
    # PREREQUISITE before adding a tool to _STAGING_REQUIRED: verify staged_id +
    # staged_field path works end-to-end first. Gate blocks inline; gating before the
    # bypass exists = hard-fail with no route through. [bug]#27972, [bug]#27973,
    # [decision]#30129, [decision]#30135.
    # Gate 35 killed S1462 -- enforcement moved to publish_gate_registry.
    # Gateway loads watched_tools/watched_fields from DB at startup via _startup().
    _STAGING_REQUIRED = {}  # empty -- DB-backed startup load handles enforcement
    _g35_fields = _STAGING_REQUIRED.get(tool_name)
    if _g35_fields and isinstance(arguments, dict):
        _g35_hits = [f for f in _g35_fields if arguments.get(f)]
        if _g35_hits:
            logger.info(
                "gate35_staging_required tool=%s fields=%s trace=%s",
                tool_name, _g35_hits, trace_id,
            )
            return _ok(req_id, {
                "content": [{"type": "text", "text": json.dumps({
                    "error": (
                        f"BLOCKED: {tool_name} field(s) {_g35_hits} must be staged, "
                        f"not passed inline. Use stage_payload() -> staged_id."
                    ),
                    "fields": _g35_hits,
                    "fix": (
                        "DB is the bus -- GCS staging is dead since S1441. "
                        "Correct path: "
                        "(1) stage_payload(payload=CONTENT, "
                        "payload_type='ddl'|'sql'|'code'|'patches'|'js'|'css'|'html', "
                        "session_key=SK) -> returns staged_id (UUID). "
                        "(2) platform_publish(..., staged_id=STAGED_ID, "
                        "staged_field='content'|'sql'|'code'|'patches'|'js', "
                        "session_key=SK). "
                        "stage_payload validates at the door before storing -- "
                        "broken code never enters the DB. "
                        "staged_id is a UUID, never a write-path field -- "
                        "Gate 35 never fires on it."
                    ),
                })}],
                "isError": True,
            })

    _wt_label(tool_name=tool_name)   # the real tool (after meta_tool unwrap) names this request's door span
    try:
        # Local handlers: ping and gateway_status never leave the gateway container
        if tool_name in _LOCAL_HANDLERS:
            result = await _LOCAL_HANDLERS[tool_name](arguments)
        else:
            result = await _proxy(tool_name, arguments, trace_id)

        # ── Inline image extraction ───────────────────────────────────────────────────
        # Tools may return _inline_image_b64 + _inline_image_mime to embed an
        # image directly in the MCP tool result so Claude sees it without a
        # separate curl+view step. Extract before JSON serialisation so the
        # b64 blob does not bloat the text block.
        #
        # db-v3 /execute wraps tool responses as {"status":"ok","result":{...}}.
        # _inline_image_b64 lives inside result["result"], not at the top level.
        # We check both levels to be forward-compatible with any response shape.
        inline_image_b64  = None
        inline_image_mime = 'image/png'
        if isinstance(result, dict):
            if result.get('_inline_image_b64'):
                # Top-level shape (local handlers or future tools)
                result            = dict(result)           # shallow copy — never mutate original
                inline_image_b64  = result.pop('_inline_image_b64')
                inline_image_mime = result.pop('_inline_image_mime', 'image/png')
            elif isinstance(result.get('result'), dict) and result['result'].get('_inline_image_b64'):
                # Wrapped shape: db-v3 /execute — {"status":"ok","result":{...,_inline_image_b64,...}}
                _inner            = dict(result['result'])  # shallow copy inner — never mutate
                inline_image_b64  = _inner.pop('_inline_image_b64')
                inline_image_mime = _inner.pop('_inline_image_mime', 'image/png')
                result            = dict(result)            # shallow copy outer
                result['result']  = _inner

        if isinstance(result, (dict, list)):
            text = json.dumps(result, default=str)
        elif result is None:
            text = json.dumps({"status": "ok"})
        else:
            text = str(result)

        # S1409: Context telemetry -- fire-and-forget response size recording
        # Toyota: store last-known session_key so tools without session_key
        # in arguments (e.g. platform_search) are still recorded.
        # S-context-estimator-2: now passes raw text (capped) for real
        # tiktoken measurement server-side, not just byte length. Task
        # reference retained in _bg_tasks -- an unreferenced asyncio task
        # is GC-eligible under Cloud Run's CPU throttling before it ever
        # runs (the exact sTR #17/#55-A pattern), so this task was at real
        # risk of silently never firing.
        global _last_known_sk
        _ct_sk = (arguments or {}).get('session_key', '') if isinstance(arguments, dict) else ''
        if _ct_sk:
            _last_known_sk = _ct_sk
        else:
            _ct_sk = _last_known_sk
        if _ct_sk and tool_name not in _LOCAL_HANDLERS:
            _ct_req_text = json.dumps(arguments, default=str) if isinstance(arguments, dict) else ''
            _ct_task = asyncio.create_task(_fire_context_telemetry(_ct_sk, tool_name, _ct_req_text, text))
            _bg_tasks.add(_ct_task)
            _ct_task.add_done_callback(_bg_tasks.discard)

        content_blocks = [{"type": "text", "text": text}]
        if inline_image_b64:
            content_blocks.append({
                "type":     "image",
                "data":     inline_image_b64,
                "mimeType": inline_image_mime,
            })

        return _ok(req_id, {"content": content_blocks})

    except Exception as exc:
        logger.error(
            "tool_call_error tool=%s trace=%s: %s", tool_name, trace_id, exc, exc_info=True
        )
        return _ok(req_id, {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "error":           str(exc),
                    "tool":            tool_name,
                    "trace_id":        trace_id,
                    "circuit_breaker": _circuit.to_dict(),
                }),
            }],
            "isError": True,
        })


async def _handle_single(msg: dict) -> dict | None:
    method = msg.get("method", "")
    req_id = msg.get("id")
    params = msg.get("params", {}) or {}
    if req_id is None:
        return None  # notification — no response per JSON-RPC spec
    handlers = {
        "initialize": _handle_initialize,
        "tools/list": _handle_tools_list,
        "tools/call": _handle_tools_call,
        "ping":       lambda p, i: _ok(i, {}),
    }
    handler = handlers.get(method)
    if handler is None:
        return _err(req_id, -32601, f"Method not found: {method}")
    _wt_label(rpc=method)
    try:
        if asyncio.iscoroutinefunction(handler):
            return await handler(params, req_id)
        return handler(params, req_id)
    except Exception as exc:
        logger.error("handler_error method=%s: %s", method, exc, exc_info=True)
        return _err(req_id, -32603, f"Internal error: {exc}")


# == § 012  ROUTES =============================================================
# POST /mcp: main MCP endpoint. Captures all headers into _upstream_hdrs.
#   Handles batch (list) and single JSON-RPC. Returns 202 for notifications.
# GET  /mcp: 405 (MCP is POST-only).
# POST /execute: REST passthrough to db-v3 /execute. X-API-Key auth.
# GET  /health: local gateway health. No I/O, no AlloyDB dependency.
#   Use gateway_status tool for full db-v3 reachability diagnostics.
# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.on_event("shutdown")
async def _wt_shutdown() -> None:
    """[decision] #51749: last flush before the instance goes away, so its final minute of counts is not lost."""
    _WT_IN_FLUSH.set(True)
    try:
        await asyncio.wait_for(_work_ticket.flush_with(_wt_write), timeout=5.0)
    except Exception as exc:
        logger.warning("work_ticket final flush failed: %s", exc)
    try:
        await asyncio.wait_for(_wt_span_flush(), timeout=5.0)
    except Exception as exc:
        logger.warning("gateway final span flush failed: %s", exc)


@app.post("/mcp")
async def mcp_post(request: Request) -> Response:
    # ── Enterprise header capture ─────────────────────────────────────────
    # Capture ALL headers from every MCP call. Three purposes:
    #   1. Discovery — log what claude.ai sends so we can find the UUID header
    #   2. Injection — auto-wire UUID into open_session (Tier 0 discovery)
    #   3. Forwarding — pass anthropic-/x-claude-/referer to db-v3 as X-Upstream-*
    raw_hdrs = dict(request.headers)
    _upstream_hdrs.set(raw_hdrs)
    # Bug 52545: /mcp gate. off = legacy no-check; warn = record unauthenticated callers, allow;
    # enforce = 401. Credential via X-API-Key, Authorization: Bearer, or ?api_key= (connector URLs).
    if MCP_AUTH_MODE != "off" and not _auth_gate(request, "/mcp", allow_query=True, mode=MCP_AUTH_MODE):
        return JSONResponse(status_code=401, content={"error": "unauthorized"})
    _interesting = {
        k: v for k, v in raw_hdrs.items()
        if any(k.lower().startswith(p) for p in (
            'anthropic-', 'x-claude-', 'x-conversation-', 'x-chat-',
            'referer', 'origin', 'user-agent', 'x-forwarded-for',
        ))
    }
    # Explicitly capture chain-correlation headers regardless of prefix match
    for _hk in ('baggage', 'traceparent', 'x-cloud-trace-context', 'x-anthropic-client'):
        if _hk in raw_hdrs:
            _interesting[_hk] = raw_hdrs[_hk]
    _uuid_hit = _extract_uuid_from_headers(raw_hdrs)
    logger.info(
        "mcp_request all_keys=%s interesting=%s uuid_extracted=%s",
        sorted(raw_hdrs.keys()),
        json.dumps(_interesting, default=str)[:800],
        _uuid_hit or "none",
    )
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content=_err(None, -32700, "Parse error"))
    if isinstance(body, list):
        results = [r for item in body if (r := await _handle_single(item)) is not None]
        return JSONResponse(content=results) if results else Response(status_code=202)
    result = await _handle_single(body)
    return JSONResponse(content=result) if result is not None else Response(status_code=202)


@app.get("/mcp")
async def mcp_get() -> Response:
    return Response(status_code=405)


def _unwrap_meta_tool_rest(tool_name: str, arguments: Any) -> tuple[str, dict, str | None]:
    # S1226E: looped unwrap -- see matching comment in _handle_tools_call. The
    # wire payload can carry more than one redundant meta_tool wrapping layer,
    # so this must loop (bounded, depth<5) rather than unwrap once.
    _depth = 0
    while tool_name == "meta_tool" and _depth < 5:
        _depth += 1
        if not isinstance(arguments, dict):
            return tool_name, {}, f"meta_tool arguments must be an object, got {type(arguments).__name__}"
        _expected_keys = {"tool_name", "arguments"}
        _unexpected = set(arguments.keys()) - _expected_keys
        if _unexpected:
            _bad = sorted(_unexpected)
            logger.error("meta_tool(rest) shape_violation unexpected_keys=%s tool=%s", _bad, arguments.get("tool_name", "?"))
            return tool_name, {}, (
                "meta_tool called with unexpected top-level argument(s): " + str(_bad) +
                ". Nest all target-tool fields inside arguments instead of passing them as siblings of tool_name."
            )
        inner = arguments.get("tool_name", "")
        inner_args = arguments.get("arguments", {}) or {}
        if isinstance(inner_args, str):
            _raw = inner_args
            if len(_raw) > _LARGE_PAYLOAD_THRESHOLD:
                return tool_name, {}, f"BLOCKED: payload too large for meta_tool inline JSON argument transport ({len(_raw)} chars, threshold {_LARGE_PAYLOAD_THRESHOLD} chars)"
            try:
                try:
                    inner_args = json.loads(inner_args.strip())
                except Exception:
                    inner_args = json.loads(_sanitize_json_escapes(inner_args.strip()))
            except Exception as _exc:
                logger.error("meta_tool(rest) inner_args parse FAILED inner_tool=%s len=%d err=%s preview=%.300r", inner, len(_raw), _exc, _raw)
                return tool_name, {}, f"meta_tool: inner arguments JSON parse failed: {_exc}"
        tool_name = inner or tool_name
        arguments = inner_args or {}
    return tool_name, (arguments or {}), None


@app.post("/execute")
async def rest_execute(request: Request) -> Response:
    """
    REST passthrough — proxies directly to db-v3 /execute.
    Preserves backward compatibility for any non-MCP callers.
    """
    if not _auth_gate(request, "/execute"):
        return JSONResponse(status_code=401, content={"error": "unauthorized"})
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid JSON"})
    tool_name = body.get("tool_name", "")
    arguments = body.get("arguments", {}) or {}
    if not tool_name:
        return JSONResponse(status_code=400, content={"error": "tool_name required"})
    tool_name, arguments, _unwrap_err = _unwrap_meta_tool_rest(tool_name, arguments)
    if _unwrap_err:
        return JSONResponse(status_code=400, content={"error": _unwrap_err})
    trace_id = _wt_trace_id()   # [decision] #51749: inherited from our caller or minted at the door
    _wt_label(tool_name=tool_name)
    try:
        result = await _proxy(tool_name, arguments, trace_id)
        return JSONResponse(content=result)
    except Exception as exc:
        _tl_error(exc, "rest_execute")   # [bug] #64738: this handler answers 502 and logs nothing, so record it here
        return JSONResponse(status_code=502, content={
            "error":    str(exc),
            "tool":     tool_name,
            "trace_id": trace_id,
        })


@app.get("/health")
async def health() -> dict:
    """
    Local gateway health — no I/O, no AlloyDB dependency.
    Use gateway_status tool for full db-v3 reachability diagnostics.
    """
    return {
        "status":          "healthy",
        "version":         GW_VERSION,
        "mode":            "stateless-proxy",
        "circuit_breaker": _circuit.to_dict(),
        "db_v3_url":       DB_V3_URL,
    }


# == S013  ADMIN ROUTES ========================================================
# /admin/restart/{service}: emergency watchdog endpoint.
# Calls miller-gcloud-runner directly -- no db-v3 dependency.
# Auth: X-API-Key header (same key as /execute).
# Also callable as MCP tool restart_service for Claude Chat sessions.
# ------------------------------------------------------------------------------
@app.post("/admin/restart/{service}")
async def admin_restart(service: str, request: Request) -> JSONResponse:
    """
    Emergency restart endpoint -- callable from curl/Tampermonkey when db-v3 is down.
    Auth: X-API-Key header required.
    Bypasses db-v3 entirely -- routes through miller-gcloud-runner only.
    Example: curl -X POST https://<gateway>/admin/restart/miller-mcp-db-v3 -H 'X-API-Key: <key>'
    """
    if not _auth_gate(request, "/admin/restart"):
        return JSONResponse(status_code=401, content={"error": "unauthorized"})
    result = await _handle_restart_service({"service": service})
    return JSONResponse(
        status_code=200 if result.get("status") == "ok" else 400,
        content=result,
    )


@app.get("/admin/restart/{service}")
async def admin_restart_info(service: str) -> JSONResponse:
    """Discovery -- tells callers to use POST."""
    return JSONResponse(status_code=405, content={
        "error": "Use POST with X-API-Key header",
        "allowed_services": sorted(_RESTARTABLE_SERVICES),
        "example": f"curl -X POST https://miller-mcp-gateway-146372550543.us-central1.run.app/admin/restart/{service} -H 'X-API-Key: <key>'",
    })
