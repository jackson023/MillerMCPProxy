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
GW_VERSION          = "3.1.1"

# S1409: Last-known session_key for context telemetry.
# Tools like platform_search don't carry session_key in arguments.
# When any tool call DOES include session_key, we store it here.
# Subsequent calls without session_key use it as fallback.
# Single-user gateway -- one active session at a time.
_last_known_sk: str = ""
GCLOUD_RUNNER_URL   = os.environ.get("GCLOUD_RUNNER_URL", "https://miller-gcloud-runner-146372550543.us-central1.run.app")
GCLOUD_RUNNER_EXEC  = f"{GCLOUD_RUNNER_URL}/execute"

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

    def __init__(self, threshold: int = 5, recovery_s: float = 30.0) -> None:
        self.threshold   = threshold
        self.recovery_s  = recovery_s
        self._failures:  int          = 0
        self._opened_at: float | None = None
        self._state:     str          = "closed"

    def record_success(self) -> None:
        if self._state != "closed":
            logger.info(
                "circuit_breaker CLOSED — db-v3 recovered after %d failures",
                self._failures,
            )
        self._failures  = 0
        self._opened_at = None
        self._state     = "closed"

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.threshold and self._state == "closed":
            self._state     = "open"
            self._opened_at = time.monotonic()
            logger.error(
                "circuit_breaker OPENED after %d consecutive failures — db-v3 considered down",
                self._failures,
            )
        elif self._state == "half-open":
            self._state     = "open"
            self._opened_at = time.monotonic()
            logger.error("circuit_breaker half-open probe FAILED — reopening")

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


async def _handle_gateway_status(_args: dict) -> dict:
    """Probes db-v3 /health and returns full gateway diagnostic state."""
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
    return {
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
                GCLOUD_RUNNER_EXEC,
                json={"tool_name": "run_gcloud", "arguments": {"command": command, "timeout": 75}},
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


_LOCAL_HANDLERS: dict[str, Any] = {
    "ping":            _handle_ping,
    "gateway_status":  _handle_gateway_status,
    "restart_service": _handle_restart_service,
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


@app.on_event("startup")
async def _startup() -> None:
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


async def _fire_context_telemetry(sk: str, tn: str, req_b: int, resp_b: int) -> None:
    """Fire-and-forget: record tool response size for context budget tracking. S1409."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0, connect=1.0)) as c:
            await c.post(DB_V3_EXECUTE, json={
                "tool_name": "record_context_telemetry",
                "arguments": {
                    "session_key": sk, "tool_name": tn,
                    "request_bytes": req_b, "response_bytes": resp_b,
                },
            }, headers={"X-API-Key": API_KEY, "Content-Type": "application/json"})
    except Exception:
        pass  # fire-and-forget -- never block MCP response


async def _handle_tools_call(params: dict, req_id: Any) -> dict:
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {}) or {}
    trace_id  = str(uuid.uuid4())

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
    _WRITE_PATH_FIELDS = ("code", "patches", "sql", "js", "yaml", "jinja", "shell", "html", "content")
    _STAGING_REQUIRED = {
        "platform_publish": _WRITE_PATH_FIELDS,
        "platform_learn": _WRITE_PATH_FIELDS,
        "pi_publish": _WRITE_PATH_FIELDS + ("section_patches",),
        "patch_tool_js": ("js",),
    }
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
        global _last_known_sk
        _ct_sk = (arguments or {}).get('session_key', '') if isinstance(arguments, dict) else ''
        if _ct_sk:
            _last_known_sk = _ct_sk
        else:
            _ct_sk = _last_known_sk
        if _ct_sk and tool_name not in _LOCAL_HANDLERS:
            _ct_req = len(json.dumps(arguments, default=str)) if isinstance(arguments, dict) else 0
            _ct_resp = len(text)
            asyncio.create_task(_fire_context_telemetry(_ct_sk, tool_name, _ct_req, _ct_resp))

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
@app.post("/mcp")
async def mcp_post(request: Request) -> Response:
    # ── Enterprise header capture ─────────────────────────────────────────
    # Capture ALL headers from every MCP call. Three purposes:
    #   1. Discovery — log what claude.ai sends so we can find the UUID header
    #   2. Injection — auto-wire UUID into open_session (Tier 0 discovery)
    #   3. Forwarding — pass anthropic-/x-claude-/referer to db-v3 as X-Upstream-*
    raw_hdrs = dict(request.headers)
    _upstream_hdrs.set(raw_hdrs)
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
    api_key = request.headers.get("x-api-key", "")
    if api_key != API_KEY:
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
    trace_id = str(uuid.uuid4())
    try:
        result = await _proxy(tool_name, arguments, trace_id)
        return JSONResponse(content=result)
    except Exception as exc:
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
    api_key = request.headers.get("x-api-key", "")
    if api_key != API_KEY:
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
