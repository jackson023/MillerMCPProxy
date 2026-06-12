"""
Miller IQ Platform — MCP Gateway v4 (Enterprise Edition)
Responsibilities: MCP tool execution ONLY.
  - Claude → meta_tool → _dispatch → AlloyDB → result
  - No IQ app HTTP routes (those belong in miller-mcp-db-v3)

Enterprise additions v4:
  - FastAPI wrapper: proper /health HTTP endpoint, CORS, GZip
  - TraceMiddleware: X-Trace-Id on every request → cloud_ops_metrics
  - Structured JSON logging: queryable fields in Cloud Logging
  - Compiled code cache: compile() once per tool version, cache in-process
  - Tool access guard: internal tools blocked at MCP layer
  - Graceful shutdown: drain in-flight requests before pool close
  - Active request tracking: prevents mid-execution SIGTERM kills
"""

import asyncio
import inspect
import json
import logging
import os
import re as _iq_re
import datetime as _iq_dt
import sys
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict

import asyncpg
import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware

# ============================================================================
# STRUCTURED JSON LOGGER
# Every log line is valid JSON — queryable by field in Cloud Logging.
# Fields: severity, message, logger, time, trace_id, tool_name, duration_ms
# ============================================================================

class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        obj: Dict[str, Any] = {
            "severity": record.levelname,
            "message":  record.getMessage(),
            "logger":   record.name,
            "time":     _iq_dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") +
                        f"{int(record.msecs):03d}Z",
        }
        for field in ("trace_id", "tool_name", "duration_ms", "tool_count"):
            if hasattr(record, field):
                obj[field] = getattr(record, field)
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(obj)

_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(_JSONFormatter())
logging.root.handlers = [_handler]
logging.root.setLevel(logging.INFO)
log = logging.getLogger("gateway")

# ============================================================================
# SECRETS
# ============================================================================

SECRETS_DIR = "/secrets"

def load_secrets() -> int:
    if not os.path.isdir(SECRETS_DIR):
        return 0
    count = 0
    for name in os.listdir(SECRETS_DIR):
        entry = os.path.join(SECRETS_DIR, name)
        if os.path.isdir(entry):
            fp = os.path.join(entry, "value")
            if os.path.isfile(fp):
                os.environ[name] = open(fp).read().strip()
                count += 1
        elif os.path.isfile(entry):
            os.environ[name] = open(entry).read().strip()
            count += 1
    return count

_n = load_secrets()
log.info("Loaded %d secrets from %s", _n, SECRETS_DIR)

# ============================================================================
# DATABASE
# ============================================================================

def _normalize_dsn(dsn: str) -> str:
    for prefix in ("postgresql+psycopg2://", "postgresql+asyncpg://", "postgres+asyncpg://"):
        if dsn.startswith(prefix):
            return "postgresql://" + dsn[len(prefix):]
    return dsn

DATABASE_URL = os.environ.get("DATABASE_URL", "")
if not DATABASE_URL:
    log.critical("DATABASE_URL not set — exiting")
    sys.exit(1)
DATABASE_URL = _normalize_dsn(DATABASE_URL)

TOOL_TIMEOUT = 300
POOL_MIN     = 2
POOL_MAX     = 10

db_pool: asyncpg.Pool = None

# ============================================================================
# UNIVERSAL TYPE COERCION
# ============================================================================

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
    'bigint': lambda v: int(v) if v not in _IQ_NULL else None,
    'integer': lambda v: int(v) if v not in _IQ_NULL else None,
    'int': lambda v: int(v) if v not in _IQ_NULL else None,
    'int4': lambda v: int(v) if v not in _IQ_NULL else None,
    'int8': lambda v: int(v) if v not in _IQ_NULL else None,
    'smallint': lambda v: int(v) if v not in _IQ_NULL else None,
    'float': lambda v: float(v) if v not in _IQ_NULL else None,
    'float4': lambda v: float(v) if v not in _IQ_NULL else None,
    'float8': lambda v: float(v) if v not in _IQ_NULL else None,
    'numeric': lambda v: float(v) if v not in _IQ_NULL else None,
    'text': lambda v: str(v) if v is not None else None,
    'varchar': lambda v: str(v) if v is not None else None,
    'boolean': lambda v: (v if isinstance(v, bool) else str(v).lower() in ('true', '1', 'yes')) if v not in _IQ_NULL else None,
    'bool': lambda v: (v if isinstance(v, bool) else str(v).lower() in ('true', '1', 'yes')) if v not in _IQ_NULL else None,
    'date': lambda v: _iq_dt.date.fromisoformat(str(v)[:10]) if v not in _IQ_NULL else None,
    'timestamp': lambda v: _iq_dt.datetime.fromisoformat(str(v)) if v not in _IQ_NULL else None,
    'timestamptz': lambda v: _iq_dt.datetime.fromisoformat(str(v)) if v not in _IQ_NULL else None,
    'jsonb': lambda v: json.dumps(v) if not isinstance(v, str) else v,
    'json': lambda v: json.dumps(v) if not isinstance(v, str) else v,
}

def _iq_heuristic(k, v):
    if v in _IQ_NULL: return None
    try:
        if _IQ_INT_PAT.search(k.lower()):   return int(v)
        if _IQ_FLOAT_PAT.search(k.lower()): return float(v)
        if _IQ_BOOL_PAT.match(k.lower()) and isinstance(v, str): return v.lower() in ('true', '1', 'yes')
    except (ValueError, TypeError): pass
    return v

def coerce_args(args, schema=None):
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

def coerce_sql_vals(sql, vals):
    out = list(vals)
    for m in _IQ_CAST_RE.finditer(sql):
        pos = int(m.group(1)) - 1
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

# ── Chain traceability ContextVar (S915) — parity with main server ────────────
import contextvars
_CHAIN_KEYS = frozenset({'_root_job_id', '_parent_job_id', '_chain_depth', '_job_id', '_origin_trace_id'})
_chain_context: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "_chain_context", default={}
)

_TOOL_GLOBALS: Dict[str, Any] = {
    "asyncio": asyncio, "httpx": httpx, "json": json, "os": os, "logger": log,
    "coerce_args": coerce_args, "coerce_sql_vals": coerce_sql_vals,
    "db_execute": db_execute, "db_fetch": db_fetch,
    "db_fetchrow": db_fetchrow, "db_fetchval": db_fetchval, "db_executemany": db_executemany,
    "_chain_context": _chain_context,
}

# ============================================================================
# COMPILED CODE CACHE
# tool_name -> (version, compiled). Evicts on version bump.
# Bounded by distinct tool count, not version history.
# ============================================================================

_CODE_CACHE: Dict[str, tuple] = {}


# ============================================================================
# AUDIT POOL — transparent actor attribution for enterprise audit trail
# Wraps asyncpg Pool so every tool DB write carries actor identity.
# fn_universal_audit_trigger reads via current_setting('app.actor', true).
# REPL-proven: set_config -> trigger capture -> reset — all green.
# ============================================================================

class _AuditPool:
    """Wraps asyncpg Pool to auto-set/reset audit actor context on acquire."""
    __slots__ = ('_pool', '_actor', '_actor_type', '_session_key')

    def __init__(self, pool, actor: str, actor_type: str = 'ai', session_key: str = ''):
        self._pool = pool
        self._actor = actor
        self._actor_type = actor_type
        self._session_key = session_key

    @asynccontextmanager
    async def acquire(self):
        async with self._pool.acquire() as conn:
            try:
                await conn.execute(
                    "SELECT set_config('app.actor', $1, false), "
                    "set_config('app.actor_type', $2, false), "
                    "set_config('app.session_key', $3, false)",
                    self._actor, self._actor_type, self._session_key,
                )
                yield conn
            finally:
                await conn.execute(
                    "SELECT set_config('app.actor', '', false), "
                    "set_config('app.actor_type', '', false), "
                    "set_config('app.session_key', '', false)"
                )

    async def fetch(self, sql, *a):
        async with self.acquire() as c: return await c.fetch(sql, *a)

    async def fetchrow(self, sql, *a):
        async with self.acquire() as c: return await c.fetchrow(sql, *a)

    async def fetchval(self, sql, *a):
        async with self.acquire() as c: return await c.fetchval(sql, *a)

    async def execute(self, sql, *a):
        async with self.acquire() as c: return await c.execute(sql, *a)

    async def executemany(self, sql, args_list):
        async with self.acquire() as c: return await c.executemany(sql, args_list)

    def __getattr__(self, name):
        return getattr(self._pool, name)

# ============================================================================
# _dispatch — EXECUTION ENGINE
# ============================================================================

async def _dispatch(tool_name: str, arguments: Dict[str, Any], trace_id: str | None = None) -> Any:
    if trace_id is None:
        trace_id = str(uuid.uuid4())

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
                _rl_scope = {"asyncpg": asyncpg, "os": os, "json": json, "db_pool": db_pool}
                exec(compile(rl_row, '<rate_limiter>', 'exec'), _rl_scope)
                rl_result = await _rl_scope['run']({'action': 'check', 'tool_name': tool_name})
                if rl_result.get('allowed') is False:
                    raise RuntimeError(f"Rate limited: {rl_result.get('reason', 'limit exceeded')}")
        except RuntimeError:
            raise
        except Exception as _rl_exc:
            log.warning("Rate limit check failed (non-fatal): %s", _rl_exc)

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT code, input_schema, operational_intel, version, tool_status "
            "FROM tool_registry WHERE name = $1 AND enabled = TRUE",
            tool_name,
        )
    if row is None:
        async with db_pool.acquire() as conn:
            count = await conn.fetchval("SELECT COUNT(*) FROM tool_registry WHERE enabled = TRUE")
        raise ValueError(
            f"Tool '{tool_name}' not found in the registry "
            f"({count} tools loaded). Check the tool name and try again."
        )

    code = row["code"]; schema = row["input_schema"]; version = row["version"]
    arguments = coerce_args(arguments, schema)

    cache_entry = _CODE_CACHE.get(tool_name)
    if cache_entry is None or cache_entry[0] != version:
        try:
            compiled = compile(code, f"<tool:{tool_name}>", "exec")
            _CODE_CACHE[tool_name] = (version, compiled)
        except SyntaxError as exc:
            raise RuntimeError(f"Tool '{tool_name}' has a syntax error: {exc}") from exc
    else:
        compiled = cache_entry[1]

    _sk = arguments.get('session_key', '') if isinstance(arguments, dict) else ''
    _audit_pool = _AuditPool(db_pool, tool_name, 'ai', _sk)
    scope: Dict[str, Any] = {**_TOOL_GLOBALS, "db_pool": _audit_pool, "_caller_tool": None, "args": arguments}

    # S915: set chain context ContextVar for auto-inheritance
    _chain = {k: arguments[k] for k in _CHAIN_KEYS if isinstance(arguments, dict) and arguments.get(k)} if isinstance(arguments, dict) else {}
    _chain_token = _chain_context.set(_chain) if _chain else None
    try:
        exec(compiled, scope)
    except SyntaxError as exc:
        raise RuntimeError(f"Tool '{tool_name}' has a syntax error: {exc}") from exc

    run_fn = scope.get("run")
    if run_fn is None:
        raise RuntimeError(f"Tool '{tool_name}' must define `async def run(args: dict) -> ...:`")
    if not inspect.iscoroutinefunction(run_fn):
        raise RuntimeError(f"Tool '{tool_name}': `run` must be async.")

    _timeout_sec = TOOL_TIMEOUT
    try:
        async with db_pool.acquire() as conn:
            _t = await conn.fetchval(
                "SELECT timeout_seconds FROM execution_timeout_config WHERE tool_name = $1",
                tool_name,
            )
        if _t is not None: _timeout_sec = _t
    except Exception:
        pass

    t0 = time.monotonic(); status = "success"; error_type = None; result = None
    try:  # noqa — _chain_token reset in outer finally below
        result = await asyncio.wait_for(run_fn(arguments), timeout=_timeout_sec)
    except asyncio.TimeoutError:
        status = "error"; error_type = "TimeoutError"
        raise RuntimeError(f"Tool '{tool_name}' timed out after {_timeout_sec}s.")
    except Exception as e:
        status = "error"; error_type = type(e).__name__; raise
    finally:
        if _chain_token is not None:
            _chain_context.reset(_chain_token)
        duration_ms = int((time.monotonic() - t0) * 1000)
        log.info(
            "Tool '%s' %s (%dms) trace=%s", tool_name, status.upper(), duration_ms, trace_id,
            extra={"trace_id": trace_id, "tool_name": tool_name, "duration_ms": duration_ms},
        )
        try:
            async with db_pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO cloud_ops_metrics "
                    "(metric_type, tool_name, duration_ms, status, error_type, metadata, trace_id) "
                    "VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)",
                    "tool_execution", tool_name, duration_ms, status, error_type,
                    json.dumps({"args_count": len(arguments) if isinstance(arguments, dict) else 0}),
                    trace_id,
                )
        except Exception:
            log.exception("Failed to log metrics for tool: %s", tool_name)

    if isinstance(result, dict) and row.get("operational_intel"):
        _oi = row["operational_intel"]
        result["_intel"] = json.loads(_oi) if isinstance(_oi, str) else _oi
    return result

_TOOL_GLOBALS["_dispatch"] = _dispatch

# ============================================================================
# MIDDLEWARE
# ============================================================================

class TraceMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        trace_id = request.headers.get("X-Trace-Id") or str(uuid.uuid4())
        request.state.trace_id = trace_id
        response = await call_next(request)
        response.headers["X-Trace-Id"] = trace_id
        return response

_active_requests: int = 0

class _ActiveRequestMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        global _active_requests
        _active_requests += 1
        try:
            return await call_next(request)
        finally:
            _active_requests -= 1

# ============================================================================
# LIFESPAN
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool
    log.info("MCP Gateway v4 starting...")
    db_pool = await asyncpg.create_pool(
        DATABASE_URL, min_size=POOL_MIN, max_size=POOL_MAX,
        command_timeout=TOOL_TIMEOUT, statement_cache_size=0,
    )
    _TOOL_GLOBALS["db_pool"] = db_pool
    tool_count = await db_pool.fetchval("SELECT count(*) FROM tool_registry WHERE enabled = true")
    log.info("Pool ready — %d enabled tools", tool_count, extra={"tool_count": int(tool_count)})

    async def _secret_refresh():
        while True:
            await asyncio.sleep(300)
            try: load_secrets()
            except Exception: log.exception("Secret refresh failed")

    refresh_task = asyncio.create_task(_secret_refresh())
    async with mcp.session_manager.run():
        try:
            yield
        finally:
            refresh_task.cancel()
            if _active_requests > 0:
                log.info("Shutdown: draining %d requests (max 8s)...", _active_requests)
                for _ in range(80):
                    if _active_requests == 0: break
                    await asyncio.sleep(0.1)
                if _active_requests > 0:
                    log.warning("Shutdown: %d requests still active — proceeding", _active_requests)
            _CODE_CACHE.clear()
            await db_pool.close()
            log.info("Shutdown complete")

# ============================================================================
# FASTMCP + FASTAPI
# ============================================================================

mcp = FastMCP(
    "MillerMCPGateway", stateless_http=True, json_response=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)

# Build sub-app once (initializes session_manager lazily).
# Must happen before lifespan so session_manager.run() can be entered.
_mcp_sub_app = mcp.streamable_http_app()

@mcp.tool()
async def meta_tool(tool_name: str, arguments: Any = None) -> Any:
    """
    Execute any tool in the registry. Internal tools (tool_status='internal')
    are blocked from direct MCP calls — platform-to-platform use only.
    """
    if db_pool:
        tool_status = await db_pool.fetchval(
            "SELECT tool_status FROM tool_registry WHERE name=$1 AND enabled=TRUE", tool_name,
        )
        if tool_status == "internal":
            return {"status": "error", "error": (
                f"Tool '{tool_name}' is internal and cannot be called directly via MCP."
            )}
    if isinstance(arguments, str):
        try: arguments = json.loads(arguments)
        except (json.JSONDecodeError, TypeError): arguments = {}
    if not isinstance(arguments, dict): arguments = {}
    return await _dispatch(tool_name, arguments)

@mcp.tool()
def ping() -> str:
    """Returns pong — verifies MCP gateway connectivity."""
    return "pong"

@mcp.tool()
async def gateway_status() -> dict:
    """Returns live health: DB status, tool count, cache stats."""
    info: Dict[str, Any] = {
        "gateway": "MCP Gateway v4 — Enterprise Edition",
        "timeout_s": TOOL_TIMEOUT, "pool": f"{POOL_MIN}-{POOL_MAX}",
        "compile_cache_size": len(_CODE_CACHE), "active_requests": _active_requests,
    }
    if os.path.isdir(SECRETS_DIR): info["secrets"] = len(os.listdir(SECRETS_DIR))
    if db_pool:
        try:
            t0 = time.monotonic()
            n = await db_pool.fetchval("SELECT count(*) FROM tool_registry WHERE enabled = true")
            info["db"] = "connected"; info["enabled_tools"] = int(n)
            info["db_latency_ms"] = round((time.monotonic() - t0) * 1000, 1)
        except Exception as exc:
            info["db"] = f"error: {exc}"
    return info

app = FastAPI(
    title="MillerMCPGateway",
    description="Miller IQ Platform MCP Gateway — tool execution layer",
    version="4.0.0", lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
    allow_methods=["GET","POST","PATCH","PUT","DELETE","OPTIONS"],
    allow_headers=["Content-Type","X-API-Key","Authorization","X-Trace-Id"],
    allow_credentials=False)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(TraceMiddleware)
app.add_middleware(_ActiveRequestMiddleware)

@app.get("/health")
async def health():
    """HTTP health endpoint for Cloud Run probes and capture_service_metrics cron."""
    db_ok = False; tool_count = 0; db_latency = None
    if db_pool:
        try:
            t0 = time.monotonic()
            await db_pool.fetchval("SELECT 1")
            db_latency = round((time.monotonic() - t0) * 1000, 1)
            db_ok = True
            tool_count = int(await db_pool.fetchval(
                "SELECT count(*) FROM tool_registry WHERE enabled = TRUE"
            ))
        except Exception:
            pass
    return {
        "status": "ok" if db_ok else "degraded",
        "service": "miller-mcp-gateway", "version": "4.0.0",
        "db": "connected" if db_ok else "unreachable",
        "db_latency_ms": db_latency, "tool_count": tool_count,
        "compile_cache_size": len(_CODE_CACHE), "active_requests": _active_requests,
    }

# Mount at / so FastMCP's internal /mcp route is reachable at /mcp externally.
app.mount("/", _mcp_sub_app)

