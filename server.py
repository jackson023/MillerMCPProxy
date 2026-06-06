"""
Miller MCP Gateway — Streamable HTTP transport, direct AlloyDB executor.

Single POST /mcp endpoint implements the MCP 2025-03-26 Streamable HTTP spec.
Connects directly to AlloyDB, reads tool_registry, exec()s tools.
No FastMCP, no middleware, no proxy hop.
"""

import asyncio
import inspect
import json
import logging
import os
import re as _iq_re
import datetime as _iq_dt
import traceback
import uuid
from typing import Any, Dict

import asyncpg
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from smart_pool import SmartPool, BigQueryPool

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("miller-mcp-gateway")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="Miller MCP Gateway", docs_url=None, redoc_url=None)

# ---------------------------------------------------------------------------
# Database pool (AlloyDB direct)
# ---------------------------------------------------------------------------
db_pool: SmartPool | None = None


@app.on_event("startup")
async def _startup():
    global db_pool
    dsn = os.environ["DATABASE_URL"]
    # asyncpg needs postgresql:// not postgresql+asyncpg://
    if "+asyncpg" in dsn:
        dsn = dsn.replace("postgresql+asyncpg", "postgresql")
    _alloydb_pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10, command_timeout=120)
    db_pool = SmartPool(_alloydb_pool, BigQueryPool())
    await db_pool.check_degraded_flag()
    logger.info("SmartPool ready — AlloyDB direct, BQ fallback armed")


@app.on_event("shutdown")
async def _shutdown():
    global db_pool
    if db_pool:
        await db_pool.close()
        logger.info("DB pool closed")


# ---------------------------------------------------------------------------
# Universal Type Coercion (copied exactly from miller-mcp-db main.py)
# ---------------------------------------------------------------------------
_IQ_NULL = (None, "", "null", "undefined", "none", "None")

_IQ_SCHEMA_FN = {
    "integer": lambda v: int(v) if v not in _IQ_NULL else None,
    "number": lambda v: float(v) if v not in _IQ_NULL else None,
    "boolean": lambda v: (
        v if isinstance(v, bool) else str(v).lower() in ("true", "1", "yes")
    )
    if v not in _IQ_NULL
    else None,
    "string": lambda v: str(v) if v is not None else None,
    "array": lambda v: (json.loads(v) if isinstance(v, str) else v)
    if v is not None
    else None,
    "object": lambda v: (json.loads(v) if isinstance(v, str) else v)
    if v is not None
    else None,
}

_IQ_INT_PAT = _iq_re.compile(
    r"(_id|_ids|_count|_limit|_offset|_page|_position|_order|_version|sort_order|^id$|^ids$)$",
    _iq_re.I,
)
_IQ_FLOAT_PAT = _iq_re.compile(
    r"(_pct|_percent|_score|_rate|_amount|_value|_price|_weight)$", _iq_re.I
)
_IQ_BOOL_PAT = _iq_re.compile(r"^(is_|has_|can_|show_|enable_|allow_)", _iq_re.I)
_IQ_CAST_RE = _iq_re.compile(r"\$(\d+)::(\w+)", _iq_re.I)
_IQ_CAST_FN = {
    "bigint": lambda v: int(v) if v not in _IQ_NULL else None,
    "integer": lambda v: int(v) if v not in _IQ_NULL else None,
    "int": lambda v: int(v) if v not in _IQ_NULL else None,
    "int4": lambda v: int(v) if v not in _IQ_NULL else None,
    "int8": lambda v: int(v) if v not in _IQ_NULL else None,
    "smallint": lambda v: int(v) if v not in _IQ_NULL else None,
    "float": lambda v: float(v) if v not in _IQ_NULL else None,
    "float4": lambda v: float(v) if v not in _IQ_NULL else None,
    "float8": lambda v: float(v) if v not in _IQ_NULL else None,
    "numeric": lambda v: float(v) if v not in _IQ_NULL else None,
    "text": lambda v: str(v) if v is not None else None,
    "varchar": lambda v: str(v) if v is not None else None,
    "boolean": lambda v: (
        v if isinstance(v, bool) else str(v).lower() in ("true", "1", "yes")
    )
    if v not in _IQ_NULL
    else None,
    "bool": lambda v: (
        v if isinstance(v, bool) else str(v).lower() in ("true", "1", "yes")
    )
    if v not in _IQ_NULL
    else None,
    "date": lambda v: _iq_dt.date.fromisoformat(str(v)[:10])
    if v not in _IQ_NULL
    else None,
    "timestamp": lambda v: _iq_dt.datetime.fromisoformat(str(v))
    if v not in _IQ_NULL
    else None,
    "timestamptz": lambda v: _iq_dt.datetime.fromisoformat(str(v))
    if v not in _IQ_NULL
    else None,
    "jsonb": lambda v: json.dumps(v) if not isinstance(v, str) else v,
    "json": lambda v: json.dumps(v) if not isinstance(v, str) else v,
}


def _iq_heuristic(k: str, v):
    if v in _IQ_NULL:
        return None
    try:
        if _IQ_INT_PAT.search(k.lower()):
            return int(v)
        if _IQ_FLOAT_PAT.search(k.lower()):
            return float(v)
        if _IQ_BOOL_PAT.match(k.lower()) and isinstance(v, str):
            return v.lower() in ("true", "1", "yes")
    except (ValueError, TypeError):
        pass
    return v


def coerce_args(args: dict, schema=None) -> dict:
    """Two-pass coercion: schema types first, heuristics second."""
    if not isinstance(args, dict):
        return args
    props = {}
    if schema:
        raw = schema if isinstance(schema, dict) else json.loads(schema)
        props = raw.get("properties", {})
    out = {}
    for k, v in args.items():
        if k in props:
            fn = _IQ_SCHEMA_FN.get(props[k].get("type"))
            if fn:
                try:
                    out[k] = fn(v)
                    continue
                except (ValueError, TypeError):
                    pass
        out[k] = _iq_heuristic(k, v)
    return out


def coerce_sql_vals(sql: str, vals) -> list:
    """Read $N::type SQL casts, coerce Python vals to match asyncpg."""
    out = list(vals)
    for m in _IQ_CAST_RE.finditer(sql):
        pos = int(m.group(1)) - 1
        cast = m.group(2).lower()
        if 0 <= pos < len(out) and cast in _IQ_CAST_FN:
            try:
                out[pos] = _IQ_CAST_FN[cast](out[pos])
            except Exception:
                pass
    return out


# ---------------------------------------------------------------------------
# DB helpers (match miller-mcp-db exactly)
# ---------------------------------------------------------------------------
async def db_execute(conn, sql, *vals):
    return await conn.execute(sql, *coerce_sql_vals(sql, vals))


async def db_fetch(conn, sql, *vals):
    return await conn.fetch(sql, *coerce_sql_vals(sql, vals))


async def db_fetchrow(conn, sql, *vals):
    return await conn.fetchrow(sql, *coerce_sql_vals(sql, vals))


async def db_fetchval(conn, sql, *vals):
    return await conn.fetchval(sql, *coerce_sql_vals(sql, vals))


async def db_executemany(conn, sql, many):
    return await conn.executemany(sql, [coerce_sql_vals(sql, v) for v in many])


# ---------------------------------------------------------------------------
# Tool globals (injected into every exec() scope)
# ---------------------------------------------------------------------------
_TOOL_GLOBALS: Dict[str, Any] = {
    "asyncio": asyncio,
    "httpx": httpx,
    "json": json,
    "os": os,
    "logger": logger,
    "coerce_args": coerce_args,
    "coerce_sql_vals": coerce_sql_vals,
    "db_execute": db_execute,
    "db_fetch": db_fetch,
    "db_fetchrow": db_fetchrow,
    "db_fetchval": db_fetchval,
    "db_executemany": db_executemany,
}


# ---------------------------------------------------------------------------
# Tool dispatch (direct DB executor — no proxy hop)
# ---------------------------------------------------------------------------
async def _dispatch(tool_name: str, arguments: Dict[str, Any]) -> Any:
    """
    Load tool code from DB, compile and run it.
    Every call reads fresh from tool_registry — no in-memory cache.
    """
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT code, input_schema FROM tool_registry "
            "WHERE name = $1 AND enabled = TRUE",
            tool_name,
        )
    if row is None:
        async with db_pool.acquire() as conn:
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM tool_registry WHERE enabled = TRUE"
            )
        raise ValueError(
            f"Tool '{tool_name}' not found in the registry "
            f"({count} tools loaded). Check the tool name and try again."
        )

    code = row["code"]
    schema = row["input_schema"]
    arguments = coerce_args(arguments, schema)

    scope: Dict[str, Any] = {
        **_TOOL_GLOBALS,
        "db_pool": db_pool,
        "_dispatch": _dispatch,
        "args": arguments,
    }

    try:
        exec(compile(code, f"<tool:{tool_name}>", "exec"), scope)
    except SyntaxError as exc:
        raise RuntimeError(f"Tool '{tool_name}' has a syntax error: {exc}") from exc

    run_fn = scope.get("run")
    if run_fn is None:
        raise RuntimeError(
            f"Tool '{tool_name}' must define `async def run(args: dict) -> ...:`"
        )

    if inspect.iscoroutinefunction(run_fn):
        return await run_fn(arguments)
    else:
        return run_fn(arguments)


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------
SERVER_INFO = {
    "name": "miller-mcp-gateway",
    "version": "1.0.0",
}

PROTOCOL_VERSION = "2025-03-26"


def _jsonrpc_ok(id, result):
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _jsonrpc_error(id, code, message, data=None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": id, "error": err}


# ---------------------------------------------------------------------------
# MCP method handlers
# ---------------------------------------------------------------------------
async def _handle_initialize(params: dict, req_id):
    """MCP initialize handshake."""
    return _jsonrpc_ok(req_id, {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": {"listChanged": False},
        },
        "serverInfo": SERVER_INFO,
    })


async def _handle_tools_list(params: dict, req_id):
    """Return ONLY meta_tool — the single gateway entry point.

    Claude Chat sees one tool. All 1,200+ platform tools are called
    through meta_tool(tool_name="...", arguments={...}).
    """
    tools = [{
        "name": "meta_tool",
        "description": (
            "Miller IQ Platform gateway. Call any of 1,200+ tools by name. "
            "Arguments: tool_name (string, required) — the tool to execute; "
            "arguments (object, optional) — the tool's input arguments."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {
                    "type": "string",
                    "description": "Name of the tool to execute"
                },
                "arguments": {
                    "type": "object",
                    "description": "Arguments to pass to the tool",
                    "default": {}
                }
            },
            "required": ["tool_name"]
        }
    }]
    return _jsonrpc_ok(req_id, {"tools": tools})


async def _handle_tools_call(params: dict, req_id):
    """Execute a tool via _dispatch — intercepts meta_tool for direct routing."""
    call_name = params.get("name", "")
    arguments = params.get("arguments", {}) or {}

    # meta_tool fast path: extract inner tool_name and dispatch directly
    # No DB round-trip for meta_tool itself — just unwrap and forward.
    if call_name == "meta_tool":
        tool_name = arguments.get("tool_name", "")
        tool_args = arguments.get("arguments", {}) or {}
        if not tool_name:
            return _jsonrpc_ok(req_id, {
                "content": [{"type": "text", "text": json.dumps({
                    "error": "tool_name is required in meta_tool arguments"
                })}],
                "isError": True,
            })
    else:
        # Direct tool call (backward compat — /execute still works)
        tool_name = call_name
        tool_args = arguments

    try:
        result = await _dispatch(tool_name, tool_args)
        if isinstance(result, dict) or isinstance(result, list):
            text = json.dumps(result, default=str)
        elif result is None:
            text = json.dumps({"status": "ok"})
        else:
            text = str(result)
        return _jsonrpc_ok(req_id, {
            "content": [{"type": "text", "text": text}],
        })
    except Exception as exc:
        tb = traceback.format_exc()
        logger.error("Tool %s failed: %s\n%s", tool_name, exc, tb)
        return _jsonrpc_ok(req_id, {
            "content": [{"type": "text", "text": json.dumps({
                "error": str(exc),
                "tool": tool_name,
            })}],
            "isError": True,
        })


# ---------------------------------------------------------------------------
# Route: POST /mcp — Streamable HTTP (MCP 2025-03-26)
# ---------------------------------------------------------------------------
@app.post("/mcp")
async def mcp_post(request: Request):
    """
    Single MCP endpoint — Streamable HTTP transport.
    Receives JSON-RPC, returns application/json.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content=_jsonrpc_error(None, -32700, "Parse error"),
        )

    # Handle batch requests
    if isinstance(body, list):
        results = []
        for item in body:
            r = await _handle_single(item)
            if r is not None:  # notifications return None
                results.append(r)
        if not results:
            return Response(status_code=202)
        return JSONResponse(content=results)

    # Single request/notification
    result = await _handle_single(body)
    if result is None:
        return Response(status_code=202)
    return JSONResponse(content=result)


async def _handle_single(msg: dict):
    """Route a single JSON-RPC message to the right handler."""
    method = msg.get("method", "")
    req_id = msg.get("id")  # None for notifications
    params = msg.get("params", {}) or {}

    # Notifications (no id) — acknowledge silently
    if req_id is None:
        # notifications/initialized, notifications/cancelled, etc.
        return None

    handlers = {
        "initialize": _handle_initialize,
        "tools/list": _handle_tools_list,
        "tools/call": _handle_tools_call,
        "ping": lambda p, i: _jsonrpc_ok(i, {}),
    }

    handler = handlers.get(method)
    if handler is None:
        return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")

    try:
        if asyncio.iscoroutinefunction(handler):
            return await handler(params, req_id)
        return handler(params, req_id)
    except Exception as exc:
        logger.error("Handler %s error: %s", method, exc, exc_info=True)
        return _jsonrpc_error(req_id, -32603, f"Internal error: {exc}")


# ---------------------------------------------------------------------------
# Route: GET /mcp — optional SSE stream (return 405 for now)
# ---------------------------------------------------------------------------
@app.get("/mcp")
async def mcp_get():
    """We don't need server-initiated messages. Return 405."""
    return Response(status_code=405)


# ---------------------------------------------------------------------------
# Route: DELETE /mcp — session termination (not needed)
# ---------------------------------------------------------------------------
@app.delete("/mcp")
async def mcp_delete():
    return Response(status_code=405)


# ---------------------------------------------------------------------------
# Route: POST /execute — plain HTTP executor for AlloyDB predict_row()
# ---------------------------------------------------------------------------
@app.post("/execute")
async def execute(request: Request):
    """
    Simple HTTP executor. AlloyDB's google_ml.predict_row() calls this.
    Expects: {"tool_name": "...", "arguments": {...}}
    Returns: JSON result from the tool.
    """
    # API key check
    api_key = request.headers.get("x-api-key", "")
    if api_key != os.environ.get("API_KEY", "miller-techstack-2026"):
        return JSONResponse(status_code=401, content={"error": "unauthorized"})

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid JSON"})

    tool_name = body.get("tool_name", "")
    arguments = body.get("arguments", {}) or {}

    if not tool_name:
        return JSONResponse(status_code=400, content={"error": "tool_name required"})

    try:
        result = await _dispatch(tool_name, arguments)
        if isinstance(result, (dict, list)):
            return JSONResponse(content=result)
        elif result is None:
            return JSONResponse(content={"status": "ok"})
        else:
            return JSONResponse(content={"result": str(result)})
    except Exception as exc:
        logger.error("Execute %s failed: %s", tool_name, exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": str(exc), "tool": tool_name},
        )


# ---------------------------------------------------------------------------
# Route: POST /api/tool-reload
# ---------------------------------------------------------------------------
@app.post("/api/tool-reload")
async def api_tool_reload(request: Request):
    logger.info("tool-reload signal received")
    return JSONResponse({"status": "ok", "message": "tools always fresh from DB"})


# ---------------------------------------------------------------------------
# Route: POST /api/alloydb-recovered
# ---------------------------------------------------------------------------
@app.post("/api/alloydb-recovered")
async def api_alloydb_recovered(request: Request):
    if db_pool and hasattr(db_pool, '_exit_degraded'):
        await db_pool._exit_degraded()
        logger.info("SmartPool: exiting degraded mode")
        return JSONResponse({"status": "ok", "degraded": False, "action": "bq_replay_pending"})
    return JSONResponse({"status": "ok", "degraded": False, "message": "already in normal mode"})


# ---------------------------------------------------------------------------
# Cloud Build Pub/Sub webhook routes
# ---------------------------------------------------------------------------
@app.post("/webhooks/cloudbuild")
async def webhook_cloudbuild(request: Request):
    """Pub/Sub push: ALL Cloud Build status events -> handle_cloudbuild_webhook."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"status": "ack", "detail": "unparseable"}, 200)
    # Return 200 immediately -- Pub/Sub requires ack within deadline.
    # handle_cloudbuild_webhook writes build_events and fires Inngest on terminal.
    asyncio.create_task(_dispatch("handle_cloudbuild_webhook", {"body": body}))
    return JSONResponse({"status": "ack"}, 200)


@app.post("/webhooks/build-complete")
async def webhook_build_complete(request: Request):
    """Pub/Sub push: SUCCESS-only Cloud Build events (finalize gate)."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"status": "ack", "detail": "unparseable"}, 200)
    # finalize_only=True: skips duplicate build_events row (already written
    # by /webhooks/cloudbuild which receives all events including SUCCESS).
    asyncio.create_task(
        _dispatch("handle_cloudbuild_webhook", {"body": body, "finalize_only": True})
    )
    return JSONResponse({"status": "ack"}, 200)

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    try:
        async with db_pool.acquire() as conn:
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM tool_registry WHERE enabled = TRUE"
            )
        return {"status": "healthy", "tools_loaded": count}
    except Exception as exc:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": str(exc)},
        )
