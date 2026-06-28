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

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("miller-mcp-gateway")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DB_V3_URL     = os.environ.get("DB_V3_URL", "https://miller-mcp-db-v3-irj2rlhsea-uc.a.run.app")
DB_V3_EXECUTE = f"{DB_V3_URL}/execute"
DB_V3_HEALTH  = f"{DB_V3_URL}/health"
API_KEY       = os.environ.get("API_KEY", "miller-techstack-2026")
GW_VERSION    = "3.0.0"

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
    'anthropic-', 'x-claude-', 'x-conversation-', 'x-chat-', 'referer', 'origin',
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
]

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


_LOCAL_HANDLERS: dict[str, Any] = {
    "ping":           _handle_ping,
    "gateway_status": _handle_gateway_status,
}

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


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------
def _ok(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}

def _err(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


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


async def _handle_tools_call(params: dict, req_id: Any) -> dict:
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {}) or {}
    trace_id  = str(uuid.uuid4())

    # arguments may arrive as a JSON string from MCP serialization
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except Exception:
            arguments = {}

    # meta_tool unwrapping: Claude calls meta_tool(tool_name=X, arguments={...})
    # Unwrap so the inner tool_name routes correctly through _proxy or _LOCAL_HANDLERS.
    if tool_name == "meta_tool":
        inner      = arguments.get("tool_name", "")
        inner_args = arguments.get("arguments", {}) or {}
        if isinstance(inner_args, str):
            try:
                inner_args = json.loads(inner_args)
            except Exception:
                inner_args = {}
        tool_name = inner or tool_name
        arguments = inner_args

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

    try:
        # Local handlers: ping and gateway_status never leave the gateway container
        if tool_name in _LOCAL_HANDLERS:
            result = await _LOCAL_HANDLERS[tool_name](arguments)
        else:
            result = await _proxy(tool_name, arguments, trace_id)

        if isinstance(result, (dict, list)):
            text = json.dumps(result, default=str)
        elif result is None:
            text = json.dumps({"status": "ok"})
        else:
            text = str(result)

        return _ok(req_id, {"content": [{"type": "text", "text": text}]})

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
    _uuid_hit = _extract_uuid_from_headers(raw_hdrs)
    logger.info(
        "mcp_request all_keys=%s interesting=%s uuid_extracted=%s",
        sorted(raw_hdrs.keys()),
        json.dumps(_interesting, default=str)[:600],
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
