import asyncio
import contextvars
import datetime as _iq_dt
import inspect
import json
import logging
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict

import asyncpg
import httpx
from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from middleware.trace_middleware import TraceMiddleware
from middleware.db_pool import ASYNCPG_POOL_CONFIG
from middleware.validators import MillerResponse
from smart_pool import SmartPool, BigQueryPool

# ── Structured JSON logging ─────────────────────────────────────────────────
class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        obj = {
            "severity": record.levelname,
            "message":  record.getMessage(),
            "logger":   record.name,
            "time":     _iq_dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.")
                        + f"{int(record.msecs):03d}Z",
        }
        for field in ("trace_id", "tool_name", "duration_ms"):
            if hasattr(record, field):
                obj[field] = getattr(record, field)
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(obj)

_log_handler = logging.StreamHandler(sys.stderr)
_log_handler.setFormatter(_JSONFormatter())
logging.root.handlers = [_log_handler]
logging.root.setLevel(logging.INFO)
logger = logging.getLogger("miller-mcp-db")

# ============================================================================
# DATABASE
# ============================================================================

def _normalize_dsn(dsn: str) -> str:
    for prefix in ("postgresql+psycopg2://", "postgresql+asyncpg://", "postgres+asyncpg://"):
        if dsn.startswith(prefix):
            return "postgresql://" + dsn[len(prefix):]
    return dsn


async def _create_pool() -> asyncpg.Pool:
    raw = os.environ.get("DATABASE_URL")
    if not raw:
        raise RuntimeError("DATABASE_URL is not set")
    dsn = _normalize_dsn(raw)
    logger.info("Connecting to database…")
    return await asyncpg.create_pool(dsn, **ASYNCPG_POOL_CONFIG)


async def _ensure_schema(pool: asyncpg.Pool) -> None:
    """Idempotent schema migration — safe to run on every startup."""
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS tool_registry (
                name         TEXT        PRIMARY KEY,
                code         TEXT        NOT NULL,
                description  TEXT        NOT NULL DEFAULT '',
                input_schema JSONB       NOT NULL DEFAULT '{}',
                version      INTEGER     NOT NULL DEFAULT 1,
                enabled      BOOLEAN     NOT NULL DEFAULT TRUE,
                created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        col_exists = await conn.fetchval(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name='tool_registry' AND column_name='tags'"
        )
        if not col_exists:
            await conn.execute(
                "ALTER TABLE tool_registry "
                "ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}'"
            )
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS frontend_errors (
                id              BIGSERIAL    PRIMARY KEY,
                module          TEXT         NOT NULL,
                error_message   TEXT         NOT NULL,
                error_stack     TEXT,
                component_stack TEXT,
                error_id        TEXT,
                url             TEXT,
                context         JSONB        NOT NULL DEFAULT '{}',
                client_ts       TIMESTAMPTZ,
                created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
            )
        """)
    logger.info("Schema ready")


# ============================================================================
# MODULE STATE
# ============================================================================

db_pool: asyncpg.Pool | None = None


# ----------------------------------------------------------------------------
# Execution graph — automatic call-chain tracking
#
# Three mechanisms record tool→tool edges across every dispatch boundary:
#
#   1. ContextVar (inline await _dispatch within same process):
#      _current_tool propagates through await chains automatically.
#
#   2. Inngest threading (_triggered_by_tool in event args):
#      fire_inngest_event injects _triggered_by_tool (from _caller_tool in
#      scope).  _dispatch strips it and uses it as the effective caller.
#
#   3. HTTP threading (x-caller-tool header on /execute):
#      /execute sets the ContextVar from the header before dispatching.
#
# _record_call_edge always runs fire-and-forget — never adds latency.
# ----------------------------------------------------------------------------
_current_tool: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "_current_tool", default=None
)

_EXEC_SKIP: frozenset[str] = frozenset({
    "log_execution_edge",   # telemetry — self-referential edge
    "open_session",         # session lifecycle
    "save_session",         # session lifecycle
    "check_context_health", # observability
})

_EXECUTE_URL_DB = (
    os.environ.get("SERVICE_URL",
                   "https://miller-mcp-db-v3-146372550543.us-central1.run.app")
    + "/execute"
)


async def _record_call_edge(caller: str, callee: str) -> None:
    """
    Record one execution edge caller → callee into tool_call_log
    and platform_knowledge_links.  Never raises.
    """
    if not db_pool:
        return
    try:
        async with db_pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO tool_call_log "
                "(tool_name, caller_tool, status, called_at) "
                "VALUES ($1, $2, 'ok', NOW())",
                callee, caller,
            )
            await conn.execute(
                """
                INSERT INTO platform_knowledge_links
                    (source_type, source_key, target_type, target_key,
                     relationship, edge_source, confidence,
                     occurrence_count, last_seen_at, payload)
                VALUES ('tool', $1, 'tool', $2,
                        'calls', 'execution_graph', 0.5,
                        1, NOW(), '{}'::jsonb)
                ON CONFLICT (source_type, source_key,
                             target_type, target_key,
                             relationship, edge_source)
                WHERE source_key  IS NOT NULL
                  AND target_key  IS NOT NULL
                  AND edge_source IS NOT NULL
                DO UPDATE SET
                    occurrence_count = platform_knowledge_links.occurrence_count + 1,
                    last_seen_at     = NOW(),
                    confidence       = LEAST(
                        1.0, platform_knowledge_links.confidence + 0.05
                    )
                """,
                caller, callee,
            )
    except Exception as exc:
        logger.warning(
            "exec-graph: failed to record %s -> %s: %s", caller, callee, exc
        )


async def _platform_call(
    tool_name: str,
    arguments: dict | None = None,
    *,
    timeout: float = 120.0,
) -> dict:
    """
    Call another platform tool via /execute, threading caller context
    automatically via the x-caller-tool header.

    Use this instead of raw httpx when a tool needs to call another tool
    across an HTTP boundary so the execution edge is recorded.
    """
    headers: dict[str, str] = {"Content-Type": "application/json"}
    current = _current_tool.get()
    if current:
        headers["x-caller-tool"] = current
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            _EXECUTE_URL_DB,
            json={"tool_name": tool_name, "arguments": arguments or {}},
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("result", data)


# ============================================================================
# TOOL EXECUTION ENGINE
# ============================================================================

import re as _iq_re, datetime as _iq_dt

_IQ_NULL = (None, '', 'null', 'undefined', 'none', 'None')

_IQ_SCHEMA_FN = {
    'integer': lambda v: int(v)   if v not in _IQ_NULL else None,
    'number':  lambda v: float(v) if v not in _IQ_NULL else None,
    'boolean': lambda v: (v if isinstance(v, bool) else str(v).lower() in ('true', '1', 'yes')) if v not in _IQ_NULL else None,
    'string':  lambda v: str(v)   if v is not None else None,
    'array':   lambda v: (json.loads(v) if isinstance(v, str) else v) if v is not None else None,
    'object':  lambda v: (json.loads(v) if isinstance(v, str) else v) if v is not None else None,
}
_IQ_INT_PAT   = _iq_re.compile(r'(_id|_ids|_count|_limit|_offset|_page|_position|_order|_version|sort_order|^id$|^ids$)$', _iq_re.I)
_IQ_FLOAT_PAT = _iq_re.compile(r'(_pct|_percent|_score|_rate|_amount|_value|_price|_weight)$', _iq_re.I)
_IQ_BOOL_PAT  = _iq_re.compile(r'^(is_|has_|can_|show_|enable_|allow_)', _iq_re.I)
_IQ_CAST_RE   = _iq_re.compile(r'\$(\d+)::(\w+)', _iq_re.I)
_IQ_CAST_FN = {
    'bigint':     lambda v: int(v)   if v not in _IQ_NULL else None,
    'integer':    lambda v: int(v)   if v not in _IQ_NULL else None,
    'int':        lambda v: int(v)   if v not in _IQ_NULL else None,
    'int4':       lambda v: int(v)   if v not in _IQ_NULL else None,
    'int8':       lambda v: int(v)   if v not in _IQ_NULL else None,
    'smallint':   lambda v: int(v)   if v not in _IQ_NULL else None,
    'float':      lambda v: float(v) if v not in _IQ_NULL else None,
    'float4':     lambda v: float(v) if v not in _IQ_NULL else None,
    'float8':     lambda v: float(v) if v not in _IQ_NULL else None,
    'numeric':    lambda v: float(v) if v not in _IQ_NULL else None,
    'text':       lambda v: str(v)   if v is not None else None,
    'varchar':    lambda v: str(v)   if v is not None else None,
    'boolean':    lambda v: (v if isinstance(v, bool) else str(v).lower() in ('true', '1', 'yes')) if v not in _IQ_NULL else None,
    'bool':       lambda v: (v if isinstance(v, bool) else str(v).lower() in ('true', '1', 'yes')) if v not in _IQ_NULL else None,
    'date':       lambda v: _iq_dt.date.fromisoformat(str(v)[:10]) if v not in _IQ_NULL else None,
    'timestamp':  lambda v: _iq_dt.datetime.fromisoformat(str(v))  if v not in _IQ_NULL else None,
    'timestamptz':lambda v: _iq_dt.datetime.fromisoformat(str(v))  if v not in _IQ_NULL else None,
    'jsonb':      lambda v: json.dumps(v) if not isinstance(v, str) else v,
    'json':       lambda v: json.dumps(v) if not isinstance(v, str) else v,
}

def _iq_heuristic(k: str, v):
    if v in _IQ_NULL: return None
    try:
        if _IQ_INT_PAT.search(k.lower()):   return int(v)
        if _IQ_FLOAT_PAT.search(k.lower()): return float(v)
        if _IQ_BOOL_PAT.match(k.lower()) and isinstance(v, str):
            return v.lower() in ('true', '1', 'yes')
    except (ValueError, TypeError): pass
    return v

def coerce_args(args: dict, schema=None) -> dict:
    if not isinstance(args, dict): return args
    props = {}
    if schema:
        raw = schema if isinstance(schema, dict) else json.loads(schema)
        props = raw.get('properties', {})
    out = {}
    for k, v in args.items():
        if k in props:
            fn = _IQ_SCHEMA_FN.get(props[k].get('type'))
            if fn:
                try: out[k] = fn(v); continue
                except (ValueError, TypeError): pass
        out[k] = _iq_heuristic(k, v)
    return out

def coerce_sql_vals(sql: str, vals) -> list:
    out = list(vals)
    for m in _IQ_CAST_RE.finditer(sql):
        pos  = int(m.group(1)) - 1
        cast = m.group(2).lower()
        if 0 <= pos < len(out) and cast in _IQ_CAST_FN:
            try: out[pos] = _IQ_CAST_FN[cast](out[pos])
            except: pass
    return out

async def db_execute(conn, sql, *vals):    return await conn.execute(sql,    *coerce_sql_vals(sql, vals))
async def db_fetch(conn, sql, *vals):      return await conn.fetch(sql,      *coerce_sql_vals(sql, vals))
async def db_fetchrow(conn, sql, *vals):   return await conn.fetchrow(sql,   *coerce_sql_vals(sql, vals))
async def db_fetchval(conn, sql, *vals):   return await conn.fetchval(sql,   *coerce_sql_vals(sql, vals))
async def db_executemany(conn, sql, many): return await conn.executemany(sql, [coerce_sql_vals(sql, v) for v in many])

_TOOL_GLOBALS: Dict[str, Any] = {
    "asyncio":        asyncio,
    "httpx":          httpx,
    "json":           json,
    "os":             os,
    "logger":         logger,
    "coerce_args":    coerce_args,
    "coerce_sql_vals":coerce_sql_vals,
    "db_execute":     db_execute,
    "db_fetch":       db_fetch,
    "db_fetchrow":    db_fetchrow,
    "db_fetchval":    db_fetchval,
    "db_executemany": db_executemany,
    "_platform_call": _platform_call,  # HTTP tool-to-tool with caller threading
}

_LEARNING_HOOKS: frozenset = frozenset({
    "write_github_file",
    "github_edit_file",
    "github_file_ops",
    "push_staged_file_to_github",
    "push_local_file_to_github",
    "push_tmp_chunks_to_github",
    "register_tool",
    "rollback_service",
    "verify_deployment_health",
    "save_session_smart",
})


async def _dispatch(tool_name: str, arguments: Dict[str, Any], trace_id: str | None = None) -> Any:
    """
    Load tool code from DB, compile and run it.
    Every call reads fresh from tool_registry — no in-memory cache.
    AUTO-INSTRUMENTED: Logs execution metrics + trace_id to cloud_ops_metrics.

    Execution graph tracking (three mechanisms):

      Mechanism 1 — ContextVar (inline await _dispatch):
        Captures caller = _current_tool.get() before overwriting context.
        Restores in finally — always, even on exceptions.

      Mechanism 2 — Inngest threading:
        When caller is None and arguments contains _triggered_by_tool,
        use that value as the effective caller and strip it from args.

      Mechanism 3 — HTTP threading:
        /execute sets the ContextVar from x-caller-tool before calling _dispatch.

      _caller_tool is injected into every tool's scope so fire_inngest_event
      can read who called it and inject _triggered_by_tool into event args.
    """
    if trace_id is None:
        trace_id = str(uuid.uuid4())

    # Capture caller at the dispatch boundary, before we become the current tool
    caller: str | None = _current_tool.get()

    # Mechanism 2: recover Inngest-threaded parent when ContextVar has no parent.
    # Strip _triggered_by_tool before coerce_args so it never leaks into the tool.
    if caller is None and isinstance(arguments, dict):
        _inngest_parent = arguments.get("_triggered_by_tool")
        if _inngest_parent and isinstance(_inngest_parent, str):
            caller    = _inngest_parent
            arguments = {k: v for k, v in arguments.items()
                         if k != "_triggered_by_tool"}

    _RATE_LIMIT_EXEMPT = frozenset({
        "rate_limiter", "db_health_check", "smoke_test_hello_world",
        "regression_runner", "pool_health_monitor", "trace_explorer",
        "schema_migration_manager", "build_session_context", "check_context_health",
    })
    if tool_name not in _RATE_LIMIT_EXEMPT:
        try:
            rl_row = await db_pool.fetchval(
                "SELECT code FROM tool_registry WHERE name='rate_limiter' AND enabled=TRUE"
            )
            if rl_row:
                _rl_scope = {"asyncpg": __import__('asyncpg'), "os": os, "json": json, "db_pool": db_pool}
                exec(compile(rl_row, '<rate_limiter>', 'exec'), _rl_scope)
                rl_result = await _rl_scope['run']({'action': 'check', 'tool_name': tool_name})
                if rl_result.get('allowed') is False:
                    raise RuntimeError(f"Rate limited: {rl_result.get('reason', 'limit exceeded')}")
        except RuntimeError:
            raise
        except Exception as _rl_exc:
            logger.warning("Rate limit check failed (non-fatal): %s", _rl_exc)
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT code, input_schema, operational_intel, version FROM tool_registry WHERE name = $1 AND enabled = TRUE",
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

    code      = row["code"]
    schema    = row["input_schema"]
    version   = row["version"]
    arguments = coerce_args(arguments, schema)

    cache_entry = _CODE_CACHE.get(tool_name)
    if cache_entry is None or cache_entry[0] != version:
        try:
            _compiled = compile(code, f"<tool:{tool_name}>", "exec")
            _CODE_CACHE[tool_name] = (version, _compiled)
        except SyntaxError as exc:
            raise RuntimeError(f"Tool '{tool_name}' has a syntax error: {exc}") from exc
    else:
        _compiled = cache_entry[1]

    scope: Dict[str, Any] = {
        **_TOOL_GLOBALS,
        "db_pool":      db_pool,
        "_caller_tool": caller,    # Mechanism 2: fire_inngest_event reads this
        "args":         arguments,
    }

    try:
        exec(_compiled, scope)
    except SyntaxError as exc:
        raise RuntimeError(f"Tool '{tool_name}' has a syntax error: {exc}") from exc

    run_fn = scope.get("run")
    if run_fn is None:
        raise RuntimeError(f"Tool '{tool_name}' must define `async def run(args: dict) -> ...:` ")
    if not inspect.iscoroutinefunction(run_fn):
        raise RuntimeError(f"Tool '{tool_name}': `run` must be async.")

    _DEFAULT_TIMEOUT = 60
    _timeout_sec = _DEFAULT_TIMEOUT
    try:
        async with db_pool.acquire() as conn:
            _t_override = await conn.fetchval(
                "SELECT timeout_seconds FROM execution_timeout_config WHERE tool_name = $1",
                tool_name,
            )
        if _t_override is not None:
            _timeout_sec = _t_override
    except Exception:
        pass

    t0         = time.monotonic()
    status     = "success"
    error_type = None
    result     = None

    # Mechanism 1: set self as current tool; finally restores parent unconditionally
    _ctx_token = _current_tool.set(tool_name)
    try:
        result = await asyncio.wait_for(run_fn(arguments), timeout=_timeout_sec)
    except asyncio.TimeoutError:
        status     = "error"
        error_type = "TimeoutError"
        raise RuntimeError(
            f"Tool '{tool_name}' timed out after {_timeout_sec}s. "
            f"Configure a longer timeout via execution_timeout_config table."
        )
    except Exception as e:
        status     = "error"
        error_type = type(e).__name__
        raise
    finally:
        _current_tool.reset(_ctx_token)  # always restore — first in finally
        duration_ms = (time.monotonic() - t0) * 1000
        try:
            async with db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO cloud_ops_metrics
                    (metric_type, tool_name, duration_ms, status, error_type, metadata, trace_id)
                    VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
                """,
                    "tool_execution", tool_name, duration_ms, status,
                    error_type, json.dumps({"args_count": len(arguments)}), trace_id,
                )
        except Exception:
            logger.exception("Failed to log metrics for tool: %s", tool_name)
        logger.info("Tool '%s' %s (%dms) trace=%s", tool_name, status.upper(), int(duration_ms), trace_id or "none")

        if tool_name in _LEARNING_HOOKS and result is not None and db_pool:
            async def _learn(tn=tool_name, a=arguments, r=result) -> None:
                try:
                    hook_code = await db_pool.fetchval(
                        "SELECT code FROM tool_registry "
                        "WHERE name='platform_learning_hook' AND enabled=TRUE"
                    )
                    if hook_code:
                        _s: Dict[str, Any] = {
                            "db_pool": db_pool, "logger": logger,
                            "asyncio": asyncio, "json": json, "os": os,
                        }
                        exec(hook_code, _s)
                        await _s["run"]({"tool_name": tn, "args": a, "result": r})
                except Exception as _le:
                    logger.warning("platform_learning_hook failed (non-fatal): %s", _le)
            asyncio.create_task(_learn())

    # Record execution edge fire-and-forget — zero latency impact.
    # Conditions: real caller, not a self-call, neither side in skip list.
    if (
        caller is not None
        and caller    != tool_name
        and caller    not in _EXEC_SKIP
        and tool_name not in _EXEC_SKIP
    ):
        asyncio.create_task(_record_call_edge(caller, tool_name))

    # --- Inject operational intelligence ---
    if isinstance(result, dict) and row.get("operational_intel"):
        _oi = row["operational_intel"]
        result["_intel"] = json.loads(_oi) if isinstance(_oi, str) else _oi

    return result

_TOOL_GLOBALS["_dispatch"] = _dispatch

# ── Compiled code cache ──────────────────────────────────────────────────────
# tool_name → (version, compiled_code_object). Evicts on version bump.
_CODE_CACHE: Dict[str, tuple] = {}


# ── Active request counter ──────────────────────────────────────────────────
_active_requests: int = 0

from starlette.middleware.base import BaseHTTPMiddleware

class _ActiveRequestMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        global _active_requests
        _active_requests += 1
        try:
            return await call_next(request)
        finally:
            _active_requests -= 1


# ============================================================================
# APP + MCP
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool
    logger.info("Starting MillerMCPDB…")

    _alloydb_pool = await _create_pool()
    await _ensure_schema(_alloydb_pool)
    db_pool = SmartPool(_alloydb_pool, BigQueryPool())
    await db_pool.check_degraded_flag()

    # Auto-recovery: if GCS degraded flag exists but AlloyDB is reachable, recover immediately.
    # Prevents stuck degraded mode after transient outages (e.g. DSN normalization fixed).
    if isinstance(db_pool, SmartPool) and db_pool._degraded:
        try:
            async with asyncio.timeout(5):
                async with _alloydb_pool.acquire() as _rc:
                    await _rc.fetchval("SELECT 1")
            logger.info("lifespan: AlloyDB reachable despite degraded flag — auto-recovering")
            await db_pool._exit_degraded()
        except Exception as _re:
            logger.warning("lifespan: auto-recovery failed — staying degraded: %s", _re)

    async with db_pool.acquire() as conn:
        count = await conn.fetchval(
            "SELECT COUNT(*) FROM tool_registry WHERE enabled = TRUE"
        )
    logger.info("Database ready: %d enabled tools in registry", count)

    await _startup_registry_check(db_pool)

    # Load dynamic crons from cron_schedules — each gets its own Inngest TriggerCron
    # function registered at the exact scheduled time. Mutates inngest_functions in-place
    # so the full manifest (static + dynamic) syncs on the first Inngest probe.
    # manage_cron_schedule + /api/inngest/sync handle re-registration when crons change.
    # This line never changes — add/remove crons via manage_cron_schedule only.
    from routers.inngest_engine import load_dynamic_crons as _load_dynamic_crons
    await _load_dynamic_crons(db_pool)
    # Load dynamic event triggers — zero-deploy: wire new event→tool via manage_inngest_event_trigger.
    from routers.inngest_engine import load_dynamic_event_triggers as _load_dynamic_event_triggers
    await _load_dynamic_event_triggers(db_pool)

    async with mcp.session_manager.run():
        yield

    logger.info("Shutting down MillerMCPDB…")
    if _active_requests > 0:
        logger.info("Shutdown: draining %d active requests (max 8s)...", _active_requests)
        for _ in range(80):
            if _active_requests == 0:
                break
            await asyncio.sleep(0.1)
        if _active_requests > 0:
            logger.warning("Shutdown: %d requests still active — proceeding", _active_requests)
    _CODE_CACHE.clear()
    if db_pool:
        await db_pool.close()


app = FastAPI(title="MillerMCPDB", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
    allow_credentials=False,
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(TraceMiddleware)
app.add_middleware(_ActiveRequestMiddleware)

mcp = FastMCP(
    "MillerMCPDB",
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)


# ============================================================================
# THE ONE MCP TOOL
# ============================================================================

@mcp.tool()
async def meta_tool(tool_name: str, arguments: Dict[str, Any] | None = None) -> Any:
    """
    Execute any tool stored in the Postgres tool registry by name.
    """
    return await _dispatch(tool_name, arguments or {})


# ============================================================================
# REST ENDPOINTS
# ============================================================================

@app.get("/health")
async def health():
    db_ok = False
    tool_count = 0
    db_latency = None
    if db_pool:
        try:
            t0 = time.monotonic()
            async with db_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
                db_latency = round((time.monotonic() - t0) * 1000, 1)
                db_ok = True
                tool_count = int(await conn.fetchval(
                    "SELECT COUNT(*) FROM tool_registry WHERE enabled = TRUE"
                ))
        except Exception:
            pass
    return {
        "status":             "ok" if db_ok else "degraded",
        "db":                 "connected" if db_ok else "unreachable",
        "db_latency_ms":      db_latency,
        "tool_count":         tool_count,
        "compile_cache_size": len(_CODE_CACHE),
        "active_requests":    _active_requests,
    }


# ============================================================================
# EMERGENCY DISASTER RECOVERY
# ============================================================================

_EMERGENCY_RESTORE_SECRET = os.environ.get("EMERGENCY_RESTORE_SECRET", "miller-emergency-2026")
_REGISTRY_MIN_TOOLS = 100


async def _restore_registry_from_history(pool: asyncpg.Pool) -> dict:
    async with pool.acquire() as conn:
        before = await conn.fetchval("SELECT COUNT(*) FROM tool_registry")
        history_tools = await conn.fetchval(
            "SELECT COUNT(DISTINCT tool_name) FROM tool_registry_history"
        )
        if history_tools == 0:
            return {"status": "error", "error": "history empty, use Cloud SQL PITR"}
        await conn.execute(
            "INSERT INTO tool_registry"
            " (name, code, description, input_schema, version, enabled, tags, updated_at)"
            " SELECT DISTINCT ON (tool_name)"
            "   tool_name, code, description, input_schema, version, TRUE, tags, NOW()"
            " FROM tool_registry_history"
            " ORDER BY tool_name, changed_at DESC"
            " ON CONFLICT (name) DO UPDATE SET"
            "   code = EXCLUDED.code,"
            "   description = EXCLUDED.description,"
            "   input_schema = EXCLUDED.input_schema,"
            "   version = EXCLUDED.version,"
            "   enabled = TRUE,"
            "   tags = EXCLUDED.tags,"
            "   updated_at = NOW()"
        )
        after = await conn.fetchval(
            "SELECT COUNT(*) FROM tool_registry WHERE enabled = TRUE"
        )
    restored = after - before
    logger.critical("EMERGENCY RESTORE: %d before, %d after, %d restored", before, after, restored)
    return {"status": "ok", "before": before, "after": after, "restored": restored,
            "history_tools": history_tools}


async def _startup_registry_check(pool: asyncpg.Pool) -> None:
    async with pool.acquire() as conn:
        count = await conn.fetchval("SELECT COUNT(*) FROM tool_registry WHERE enabled = TRUE")
    if count < _REGISTRY_MIN_TOOLS:
        logger.critical("STARTUP SELF-HEAL: %d tools (min %d). Auto-restoring.", count, _REGISTRY_MIN_TOOLS)
        result = await _restore_registry_from_history(pool)
        logger.critical("STARTUP SELF-HEAL result: %s", result)
    else:
        logger.info("Registry health: %d tools (min %d) OK", count, _REGISTRY_MIN_TOOLS)


@app.post("/emergency-restore")
async def emergency_restore(request: Request):
    secret = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not secret:
        try:
            body = await request.json()
            secret = body.get("secret", "")
        except Exception:
            pass
    if secret != _EMERGENCY_RESTORE_SECRET:
        return JSONResponse({"status": "error", "error": "Unauthorized"}, status_code=401)
    if not db_pool:
        return JSONResponse({"status": "error", "error": "DB pool unavailable"}, status_code=503)
    result = await _restore_registry_from_history(db_pool)
    return JSONResponse(result, status_code=200 if result["status"] == "ok" else 500)


api_v1 = APIRouter(prefix="/api/v1")


@api_v1.post("/errors")
async def client_error_report(request: Request):
    try:
        body = await request.json()
    except Exception:
        return Response(status_code=204)
    module          = str(body.get("module", "unknown"))[:50]
    error_message   = str(body.get("error_message", ""))[:1000]
    error_stack     = body.get("error_stack")
    component_stack = body.get("component_stack")
    error_id        = str(body.get("error_id", ""))[:100]
    url             = str(body.get("url", ""))[:500]
    context         = body.get("context") if isinstance(body.get("context"), dict) else {}
    timestamp       = body.get("timestamp")
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO frontend_errors
                        (module, error_message, error_stack, component_stack,
                         error_id, url, context, client_ts)
                    VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::timestamptz)
                """,
                    module, error_message, error_stack, component_stack,
                    error_id, url, json.dumps(context), timestamp,
                )
        except Exception:
            logger.exception(
                "Failed to store frontend error (module=%s error_id=%s)", module, error_id
            )
    return Response(status_code=204)


app.include_router(api_v1)


# ============================================================================
# SMARTPOOL — DEGRADED MODE API ENDPOINTS (module-level — fixed from nested bug)
# ============================================================================

@app.post("/api/tool-reload")
async def api_tool_reload(request: Request):
    """
    Pub/Sub push handler: tool hot-reload signal in degraded mode.
    In degraded mode, _dispatch reads tool code from SmartPool (BQ) on every call.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    import base64 as _b64
    message  = body.get("message", {})
    data_b64 = message.get("data", "")
    payload  = {}
    if data_b64:
        try:
            payload = json.loads(_b64.b64decode(data_b64 + "==").decode("utf-8"))
        except Exception:
            pass
    tool_name = payload.get("tool_name") or message.get("attributes", {}).get("tool_name")
    logger.info("api_tool_reload: tool=%s — degraded-mode reload signal received", tool_name)
    return {"status": "ok", "tool_name": tool_name,
            "note": "dispatch reads fresh from SmartPool on every call"}


@app.post("/api/alloydb-recovered")
async def api_alloydb_recovered(request: Request):
    """
    Pub/Sub push handler: AlloyDB recovery signal.
    Verifies AlloyDB is reachable, then calls SmartPool._exit_degraded().
    Returns 503 if AlloyDB is still unreachable (Pub/Sub will retry).
    """
    global db_pool
    logger.info("api_alloydb_recovered: recovery signal received")

    if not isinstance(db_pool, SmartPool):
        return {"status": "ok", "message": "SmartPool not active, nothing to do"}

    if not db_pool._degraded:
        return {"status": "ok", "message": "not in degraded mode, no action needed"}

    try:
        async with asyncio.timeout(5):
            async with db_pool._alloydb.acquire() as conn:
                await conn.fetchval("SELECT 1")
    except Exception as e:
        logger.warning("api_alloydb_recovered: AlloyDB still unreachable: %s", e)
        return JSONResponse(
            {"status": "error", "message": f"AlloyDB not ready: {e}"},
            status_code=503
        )

    await db_pool._exit_degraded()
    logger.info("api_alloydb_recovered: SmartPool exited degraded mode successfully")
    return {"status": "ok", "message": "SmartPool exited degraded mode, AlloyDB restored"}


@app.post("/execute")
async def rest_execute(request: Request):
    """
    Mechanism 3 — HTTP caller threading:
    If the caller sets x-caller-tool header, wire it as the ContextVar
    before dispatching so edges are captured by the normal ContextVar path.
    """
    try:
        body      = await request.json()
        tool_name = body.get("tool_name")
        arguments = body.get("arguments", body.get("args", {}))
        if not tool_name:
            return JSONResponse({"error": "Missing tool_name"}, status_code=400)
        trace_id = getattr(request.state, 'trace_id', None)
        # Thread HTTP caller into ContextVar — stripped/empty header is ignored
        _http_caller = request.headers.get("x-caller-tool", "").strip() or None
        _http_token: contextvars.Token | None = (
            _current_tool.set(_http_caller) if _http_caller else None
        )
        try:
            result = await _dispatch(tool_name, arguments, trace_id=trace_id)
            return {"status": "ok", "result": result}
        except (ValueError, RuntimeError) as exc:
            return JSONResponse({"status": "error", "error": str(exc)}, status_code=400)
        except Exception as exc:
            logger.exception("/execute internal error")
            return JSONResponse({"status": "error", "error": str(exc)}, status_code=500)
        finally:
            if _http_token is not None:
                _current_tool.reset(_http_token)  # always restore
    except Exception as exc:
        return JSONResponse({"error": "invalid JSON"}, status_code=400)


# ============================================================================
# GENERIC IQ DISPATCHER
# ============================================================================

_iq_dispatcher = APIRouter(tags=["iq-apps"])

# ── Render cache — GET only, opt-in via cache_ttl_seconds in router result.
_RENDER_CACHE: Dict[str, tuple] = {}  # key → (expires_at, response)


async def _iq_dispatch(app_prefix: str, method: str, slug: str, request: Request) -> Response:
    tool_name = f"{app_prefix}_router_tool"
    try:
        query_params = dict(request.query_params)
        body: Dict[str, Any] = {}
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            try:
                body = await request.json()
            except Exception:
                body = dict(await request.form())
        trace_id = getattr(request.state, "trace_id", None)
        cookie = request.headers.get("cookie", "")

        _cache_key = None
        if method == "GET":
            _qs = str(request.query_params)
            _cache_key = f"{app_prefix}:{slug}:{_qs}"
            _cached = _RENDER_CACHE.get(_cache_key)
            if _cached and time.monotonic() < _cached[0]:
                return _cached[1]

        result = await _dispatch(tool_name, {
            "method":       method,
            "slug":         slug,
            "query_params": query_params,
            "body":         body,
            "cookie":       cookie,
            "headers":      dict(request.headers),
            "client_ip":    request.client.host if request.client else None,
            "base_url":     str(request.base_url),
            "path":         str(request.url.path),
            "content_type": request.headers.get("content-type", ""),
        }, trace_id=trace_id)
        if not isinstance(result, dict):
            return JSONResponse({"error": f"{tool_name} returned non-dict"}, status_code=500)
        status_code = int(result.get("status_code", 200))
        headers = result.get("headers") or {}
        _cache_ttl = result.get("cache_ttl_seconds")
        if "redirect" in result:
            return RedirectResponse(url=str(result["redirect"]), status_code=status_code, headers=headers)
        if "html" in result:
            _resp = HTMLResponse(content=result["html"], status_code=status_code, headers=headers)
            if _cache_key and _cache_ttl and status_code == 200:
                _RENDER_CACHE[_cache_key] = (time.monotonic() + float(_cache_ttl), _resp)
            return _resp
        if "js" in result:
            js_headers = {"Cache-Control": "public, max-age=300"}
            js_headers.update(headers)
            return Response(content=result["js"], media_type="application/javascript; charset=utf-8",
                            status_code=status_code, headers=js_headers)
        if "css" in result:
            css_headers = {"Cache-Control": "public, max-age=300"}
            css_headers.update(headers)
            return Response(content=result["css"], media_type="text/css; charset=utf-8",
                            status_code=status_code, headers=css_headers)
        if "sse_stream" in result:
            from fastapi.responses import StreamingResponse as _SR
            sse_headers = {
                "Content-Type":  "text/event-stream",
                "Cache-Control": "no-store",
                "X-Accel-Buffering": "no",
            }
            sse_headers.update(result.get("headers") or {})
            return _SR(content=result["sse_stream"], media_type="text/event-stream", headers=sse_headers)
        if "raw" in result:
            media_type = result.get("media_type", "application/octet-stream")
            return Response(content=result["raw"], media_type=media_type,
                            status_code=status_code, headers=headers)
        if "json" in result:
            return JSONResponse(content=result["json"], status_code=status_code)
        logger.error("_iq_dispatch: %s returned no recognised response key — keys: %s",
                     tool_name, list(result.keys()))
        return JSONResponse({"error": f"{tool_name} returned no recognised response key"}, status_code=500)
    except ValueError as exc:
        html = (
            "<!DOCTYPE html><html lang='en'><head><title>Not Found | ImpactIQ</title>"
            "<link href='https://fonts.googleapis.com/css2?family=Urbanist:wght@400;600&display=swap' rel='stylesheet'>"
            "<style>body{font-family:Urbanist,sans-serif;background:#e2e0d8;display:flex;"
            "align-items:center;justify-content:center;min-height:100vh;margin:0}"
            ".ec{background:rgba(255,255,255,0.70);border-radius:18px;padding:32px 40px;"
            "max-width:500px;backdrop-filter:blur(28px);}"
            ".ec h1{font-size:18px;font-weight:600;color:#8a1010}"
            ".ec p{font-size:13px;color:rgba(0,0,0,0.50)}"
            "</style></head><body>"
            f"<div class='ec'><h1>App not available</h1><p>{exc}</p></div>"
            "</body></html>"
        )
        return HTMLResponse(content=html, status_code=404)
    except Exception as exc:
        logger.exception("_iq_dispatch error app=%s slug=%s", app_prefix, slug)
        return JSONResponse({"error": str(exc)}, status_code=500)


# Hardcoded per-app routes removed — generic /{app}/{slug} catch-all covers all IQ apps.


@_iq_dispatcher.get("/{app}")
async def iq_app_no_slash(app: str, request: Request):
    router_tool = f"{app}_router_tool"
    exists = await db_pool.fetchval(
        "SELECT 1 FROM tool_registry WHERE name=$1 AND enabled=TRUE", router_tool
    )
    if not exists:
        return HTMLResponse(
            f"<!DOCTYPE html><html><body><h1>404</h1><p>No IQ app at /{app}</p></body></html>",
            status_code=404,
        )
    from fastapi.responses import RedirectResponse as _RR
    return _RR(url=f"/{app}/", status_code=301)

@_iq_dispatcher.get("/{app}/")
async def iq_app_root(app: str, request: Request):
    router_tool = f"{app}_router_tool"
    exists = await db_pool.fetchval(
        "SELECT 1 FROM tool_registry WHERE name=$1 AND enabled=TRUE", router_tool
    )
    if not exists:
        return HTMLResponse(
            f"<!DOCTYPE html><html><body><h1>404</h1><p>No IQ app at /{app}/</p></body></html>",
            status_code=404,
        )
    return await _iq_dispatch(app, "GET", "", request)

@_iq_dispatcher.api_route("/{app}/{slug:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def iq_app_slug(app: str, slug: str, request: Request):
    router_tool = f"{app}_router_tool"
    exists = await db_pool.fetchval(
        "SELECT 1 FROM tool_registry WHERE name=$1 AND enabled=TRUE", router_tool
    )
    if not exists:
        return HTMLResponse(
            f"<!DOCTYPE html><html><body><h1>404</h1><p>No IQ app at /{app}/{slug}</p></body></html>",
            status_code=404,
        )
    return await _iq_dispatch(app, request.method, slug, request)


# ============================================================================
# ROUTER INCLUDES
# ============================================================================

import inngest.fast_api
from routers.external_router import inngest_client, inngest_functions, external_router
from routers.admin import admin_router
from routers.events import events_router
from routers.scheduler import scheduler_router
from routers.pipeline import pipeline_router
from routers.ingest import ingest_router
from routers.stockiq import stockiq_router
from routers.storybook import storybook_router
from routers.upload import upload_router

app.include_router(admin_router)
app.include_router(events_router)
app.include_router(scheduler_router)
app.include_router(pipeline_router)
app.include_router(ingest_router)
app.include_router(external_router)
app.include_router(stockiq_router)
app.include_router(storybook_router)


# ── /api/inngest/sync ─────────────────────────────────────────────────────────
# Hot-reloads dynamic crons + event triggers from DB into inngest_functions.
# Called by manage_cron_schedule after every add/update/enable/disable.
# Without this route: new crons exist in DB but Inngest Cloud never sees them.
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/api/inngest/sync")
async def inngest_sync_route():
    from routers.inngest_engine import (
        load_dynamic_crons           as _sync_crons,
        load_dynamic_event_triggers  as _sync_events,
    )
    n_crons  = await _sync_crons(db_pool)
    n_events = await _sync_events(db_pool)
    # Best-effort: ask Inngest Cloud to re-probe our manifest
    _notified = False
    try:
        import httpx as _hx_sync
        _sk    = os.environ.get("INNGEST_SIGNING_KEY", "")
        _svcurl = _INNGEST_SERVE_ORIGIN
        async with _hx_sync.AsyncClient(timeout=10) as _c:
            _r = await _c.put(
                "https://api.inngest.com/fn/register",
                json={"url": f"{_svcurl}/api/inngest"},
                headers={"Authorization": f"Bearer {_sk}"},
            )
        _notified = _r.status_code == 200
        if not _notified:
            logger.warning("inngest_sync: Inngest Cloud probe HTTP %s: %s",
                           _r.status_code, _r.text[:120])
    except Exception as _sync_exc:
        logger.warning("inngest_sync: notify non-fatal: %s", _sync_exc)
    return {
        "status":              "ok",
        "crons_loaded":        n_crons,
        "event_triggers_loaded": n_events,
        "inngest_notified":    _notified,
    }

_INNGEST_SERVE_ORIGIN = os.environ.get("SERVICE_URL", "https://miller-mcp-db-v3-146372550543.us-central1.run.app")
inngest.fast_api.serve(app, inngest_client, inngest_functions, serve_origin=_INNGEST_SERVE_ORIGIN)

app.include_router(_iq_dispatcher)
app.include_router(upload_router)

app.mount("/mcp", mcp.streamable_http_app())


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))

