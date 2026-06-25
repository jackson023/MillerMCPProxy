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

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("miller-mcp-gateway")

app = FastAPI(title="Miller MCP Gateway", docs_url=None, redoc_url=None)

db_pool: asyncpg.Pool | None = None

@app.on_event("startup")
async def _startup():
    global db_pool
    dsn = os.environ["DATABASE_URL"]
    if "+asyncpg" in dsn:
        dsn = dsn.replace("postgresql+asyncpg", "postgresql")
    db_pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10, command_timeout=120)
    logger.info("DB pool ready — connected to AlloyDB")

@app.on_event("shutdown")
async def _shutdown():
    global db_pool
    if db_pool:
        await db_pool.close()

async def _dispatch(tool_name: str, arguments: dict) -> Any:
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT code, input_schema FROM tool_registry WHERE name = $1 AND enabled = TRUE",
            tool_name,
        )
    if row is None:
        async with db_pool.acquire() as conn:
            count = await conn.fetchval("SELECT COUNT(*) FROM tool_registry WHERE enabled = TRUE")
        raise ValueError(f"Tool '{tool_name}' not found ({count} tools loaded).")

    code = row["code"]
    schema = row["input_schema"]
    if schema and isinstance(schema, str):
        try:
            schema = json.loads(schema)
        except Exception:
            schema = {}

    scope: dict = {
        "asyncio": asyncio, "httpx": httpx, "json": json, "os": os,
        "logger": logger, "db_pool": db_pool, "_dispatch": _dispatch, "args": arguments,
    }

    try:
        exec(compile(code, f"<tool:{tool_name}>", "exec"), scope)
    except SyntaxError as exc:
        raise RuntimeError(f"Tool '{tool_name}' syntax error: {exc}") from exc

    run_fn = scope.get("run")
    if run_fn is None:
        raise RuntimeError(f"Tool '{tool_name}' must define async def run(args):")
    if inspect.iscoroutinefunction(run_fn):
        return await run_fn(arguments)
    return run_fn(arguments)

def _ok(id, result):
    return {"jsonrpc": "2.0", "id": id, "result": result}

def _err(id, code, message):
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}

async def _handle_initialize(params, req_id):
    return _ok(req_id, {
        "protocolVersion": "2025-03-26",
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": "miller-mcp-gateway", "version": "2.0.0"},
    })

async def _handle_tools_list(params, req_id):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT name, description, input_schema FROM tool_registry WHERE enabled = TRUE ORDER BY name"
        )
    tools = []
    for r in rows:
        schema = r["input_schema"]
        if isinstance(schema, str):
            try: schema = json.loads(schema)
            except: schema = {}
        tools.append({
            "name": r["name"],
            "description": r["description"] or "",
            "inputSchema": schema or {"type": "object", "properties": {}},
        })
    return _ok(req_id, {"tools": tools})

async def _handle_tools_call(params, req_id):
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {}) or {}
    try:
        result = await _dispatch(tool_name, arguments)
        if isinstance(result, (dict, list)):
            text = json.dumps(result, default=str)
        elif result is None:
            text = json.dumps({"status": "ok"})
        else:
            text = str(result)
        return _ok(req_id, {"content": [{"type": "text", "text": text}]})
    except Exception as exc:
        logger.error("Tool %s failed: %s", tool_name, exc, exc_info=True)
        return _ok(req_id, {
            "content": [{"type": "text", "text": json.dumps({"error": str(exc), "tool": tool_name})}],
            "isError": True,
        })

async def _handle_single(msg: dict):
    method = msg.get("method", "")
    req_id = msg.get("id")
    params = msg.get("params", {}) or {}
    if req_id is None:
        return None
    handlers = {
        "initialize": _handle_initialize,
        "tools/list": _handle_tools_list,
        "tools/call": _handle_tools_call,
        "ping": lambda p, i: _ok(i, {}),
    }
    handler = handlers.get(method)
    if handler is None:
        return _err(req_id, -32601, f"Method not found: {method}")
    try:
        if asyncio.iscoroutinefunction(handler):
            return await handler(params, req_id)
        return handler(params, req_id)
    except Exception as exc:
        logger.error("Handler %s error: %s", method, exc, exc_info=True)
        return _err(req_id, -32603, f"Internal error: {exc}")

@app.post("/mcp")
async def mcp_post(request: Request):
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
async def mcp_get():
    return Response(status_code=405)

@app.post("/execute")
async def execute(request: Request):
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
        return JSONResponse(content={"result": str(result)} if result else {"status": "ok"})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc), "tool": tool_name})

@app.get("/health")
async def health():
    try:
        async with db_pool.acquire() as conn:
            count = await conn.fetchval("SELECT COUNT(*) FROM tool_registry WHERE enabled = TRUE")
        return {"status": "healthy", "tools_loaded": count, "version": "2.0.0"}
    except Exception as exc:
        return JSONResponse(status_code=503, content={"status": "unhealthy", "error": str(exc)})
