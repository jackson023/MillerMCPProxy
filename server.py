"""
Miller IQ Platform — MCP Gateway v5 (S1038 Forward + Repair Edition)

Execution strategy:
  Normal path: forward every tool call to miller-mcp-db-v3 /execute via OIDC.
    Auto-parity: main.py owns ALL execution logic. No divergence possible.
  Repair path: if mcpdb returns 502/503/connect error/timeout, fall back to
    local execution ONLY for tools tagged tool_status='repair' in tool_registry.
    This preserves MCP access during main.py outages for diagnostics + recovery.

Why OIDC forward instead of copying _dispatch:
  Copying _dispatch creates two diverging engines that require manual sync.
  Forwarding via OIDC means every main.py improvement (S1037 error snippets,
  learning hooks, genie_id extraction, SmartPool) applies to MCP calls instantly.

Responsibilities: MCP protocol adapter + repair fallback only.
  - Claude -> meta_tool -> _dispatch -> mcpdb /execute -> result  (normal)
  - Claude -> meta_tool -> _dispatch -> local exec (repair tools only)  (fallback)
  - No IQ app HTTP routes (those belong in miller-mcp-db-v3)
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
import contextvars
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
        for field in ("trace_id", "tool_name", "duration_ms", "tool_count", "mcpdb_status"):
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

_DSN_PREFIXES = ("postgresql+psycopg2://", "postgresql+asyncpg://", "postgres+asyncpg://")

def _normalize_dsn(dsn: str) -> str:
    for prefix in _DSN_PREFIXES:
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
            except Exception: pass
    return out

async def db_execute(conn, sql, *vals):    return await conn.execute(sql,    *coerce_sql_vals(sql, vals))
async def db_fetch(conn, sql, *vals):      return await conn.fetch(sql,      *coerce_sql_vals(sql, vals))
async def db_fetchrow(conn, sql, *vals):   return await conn.fetchrow(sql,   *coerce_sql_vals(sql, vals))
async def db_fetchval(conn, sql, *vals):   return await conn.fetchval(sql,   *coerce_sql_vals(sql, vals))
async def db_executemany(conn, sql, many): return await conn.executemany(sql, [coerce_sql_vals(sql, v) for v in many])

# ============================================================================
# CONTEXTVARS
# ============================================================================

_CHAIN_KEYS = frozenset({'_root_job_id', '_parent_job_id', '_chain_depth', '_job_id', '_origin_trace_id'})
_chain_context: contextvars.ContextVar[dict] = contextvars.ContextVar("_chain_context", default={})
_trace_ctx: contextvars.ContextVar[dict] = contextvars.ContextVar("_trace_ctx", default={})
_request_meta: contextvars.ContextVar[dict] = contextvars.ContextVar("_request_meta", default={})
_current_tool: contextvars.ContextVar[str | None] = contextvars.ContextVar("_current_tool", default=None)


class JobPaused(Exception):
    def __init__(self, job_id, status, checkpoint=None):
        self.job_id = job_id; self.status = status; self.checkpoint = checkpoint
        super().__init__(f"Job {job_id} {status}")


# ============================================================================
# SPAN TELEMETRY
# ============================================================================

async def _emit_span(
    trace_id: str, span_id: str, parent_span_id: str | None,
    service: str, operation: str, tool_name: str | None,
    duration_ms: int, status: str,
    error_type: str | None = None, error_msg: str | None = None,
    attributes: dict | None = None,
) -> None:
    if not db_pool:
        return
    try:
        async with db_pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO platform_traces "
                "(trace_id, span_id, parent_span_id, service, operation, "
                " tool_name, duration_ms, status, error_type, error_msg, attributes) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)",
                trace_id, span_id, parent_span_id, service, operation,
                tool_name, duration_ms, status, error_type, error_msg,
                json.dumps(attributes or {}),
            )
    except Exception:
        pass


# ============================================================================
# ERROR BUS + S1037 CODE SNIPPETS
# ============================================================================

async def _attach_error_snippet(
    err_id: int, tool_name: str,
    error_name: str | None, stack_trace: str | None,
) -> None:
    """S1037: Attach source context lines to error bus row. Fire-and-forget."""
    if not db_pool:
        return
    try:
        import re as _re
        async with db_pool.acquire() as _conn:
            _row = await _conn.fetchrow(
                "SELECT code FROM tool_registry WHERE name = $1 AND enabled = TRUE LIMIT 1",
                tool_name,
            )
        if not _row or not _row['code']:
            return
        _lines = _row['code'].splitlines()
        _line_num = None
        if stack_trace:
            _m = _re.search(r'File "<tool:[^>]+>", line (\d+)', stack_trace)
            if _m:
                _line_num = int(_m.group(1))
        if _line_num:
            _start = max(0, _line_num - 4)
            _end   = min(len(_lines), _line_num + 3)
        else:
            _start, _end = 0, min(30, len(_lines))
            if error_name:
                for _i, _ln in enumerate(_lines):
                    if error_name in _ln:
                        _start = max(0, _i - 3)
                        _end   = min(len(_lines), _i + 5)
                        break
        _snippet = '\n'.join(
            '{}{:4d}  {}'.format(
                '->' if _line_num and (i + 1 == _line_num) else '  ',
                i + 1, _lines[i],
            )
            for i in range(_start, _end)
        )[:3000]
        await db_pool.execute(
            "UPDATE platform_error_bus SET code_snippet = $1 WHERE id = $2",
            _snippet, err_id,
        )
    except Exception:
        pass


async def _write_error_bus(
    source: str,
    tool_name: str | None = None,
    job_id: str | None = None,
    error_name: str | None = None,
    error_msg: str | None = None,
    stack_trace: str | None = None,
    context: dict | None = None,
    trace_id: str | None = None,
) -> None:
    """S932+S1037: Error capture with RETURNING id -> _attach_error_snippet. Never raises."""
    if not db_pool:
        return
    try:
        _err_id = await db_pool.fetchval(
            "INSERT INTO platform_error_bus "
            "(source, tool_name, job_id, error_name, error_msg, stack_trace, context, trace_id) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8) RETURNING id",
            source,
            (tool_name or '')[:200],
            (job_id or '')[:200],
            (error_name or '')[:200],
            (error_msg or '')[:500],
            (stack_trace or '')[:5000],
            json.dumps(context or {}),
            trace_id or None,
        )
        if _err_id and tool_name:
            asyncio.create_task(_attach_error_snippet(_err_id, tool_name, error_name, stack_trace))
    except Exception:
        pass


async def _write_assertion(
    assertion_type: str, target: str | None, status: str,
    expected: dict | None = None, actual: dict | None = None,
    message: str | None = None, trace_id: str | None = None,
    span_id: str | None = None, tool_name_ctx: str | None = None,
) -> None:
    if not db_pool:
        return
    try:
        await db_pool.execute(
            "INSERT INTO platform_assertions "
            "(trace_id, span_id, tool_name, assertion_type, target, status, expected, actual, message) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9)",
            trace_id or None, span_id or None, (tool_name_ctx or '')[:200],
            assertion_type[:100], (target or '')[:200], status[:20],
            json.dumps(expected) if expected is not None else None,
            json.dumps(actual) if actual is not None else None,
            (message or '')[:500],
        )
    except Exception:
        pass


async def _assert_output(result, schema, tool_name, trace_id, span_id=None):
    try:
        if result is None:
            await _write_assertion('output_contract', tool_name, 'fail',
                expected={'type': 'dict'}, actual={'type': 'null'},
                message='Tool returned None', trace_id=trace_id,
                span_id=span_id, tool_name_ctx=tool_name)
            return
        if schema:
            raw = schema if isinstance(schema, dict) else json.loads(schema)
            for key in raw.get('required', []):
                if not isinstance(result, dict) or key not in result:
                    await _write_assertion('output_contract', tool_name, 'fail',
                        expected={'key': key, 'present': True},
                        actual={'key': key, 'present': False},
                        message=f'Required output key missing: {key}',
                        trace_id=trace_id, span_id=span_id, tool_name_ctx=tool_name)
    except Exception:
        pass


# ============================================================================
# AUDIT POOL
# ============================================================================

class _AuditPool:
    __slots__ = ('_pool', '_actor', '_actor_type', '_session_key', '_job_id')

    def __init__(self, pool, actor: str, actor_type: str = 'ai',
                 session_key: str = '', job_id: str = ''):
        self._pool = pool; self._actor = actor; self._actor_type = actor_type
        self._session_key = session_key; self._job_id = job_id

    @asynccontextmanager
    async def acquire(self):
        async with self._pool.acquire() as conn:
            try:
                try:
                    await conn.execute(
                        "SELECT set_config('app.actor', $1, false), "
                        "set_config('app.actor_type', $2, false), "
                        "set_config('app.session_key', $3, false)",
                        self._actor, self._actor_type, self._session_key,
                    )
                    if self._job_id:
                        await conn.execute(f"SET application_name = 'miller:job:{self._job_id}'")
                except Exception:
                    pass
                yield conn
            finally:
                try:
                    await conn.execute(
                        "SELECT set_config('app.actor', '', false), "
                        "set_config('app.actor_type', '', false), "
                        "set_config('app.session_key', '', false)"
                    )
                except Exception:
                    pass

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
    def __getattr__(self, name): return getattr(self._pool, name)


# ============================================================================
# COMPILED CODE CACHE
# ============================================================================

_CODE_CACHE: Dict[str, tuple] = {}


# ============================================================================
# TOOL GLOBALS — repair execution scope
# ============================================================================

async def _repair_platform_call(tool_name: str, arguments: dict | None = None, **_kw) -> dict:
    raise RuntimeError(
        f"_platform_call('{tool_name}') unavailable in repair mode — "
        f"mcpdb is unreachable. Repair tools must be self-contained."
    )

async def _job_checkpoint(job_id, progress_pct=None, progress_note=None, checkpoint=None):
    return True

_TOOL_GLOBALS: Dict[str, Any] = {
    "asyncio": asyncio, "httpx": httpx, "json": json, "os": os, "logger": log,
    "coerce_args": coerce_args, "coerce_sql_vals": coerce_sql_vals,
    "db_execute": db_execute, "db_fetch": db_fetch,
    "db_fetchrow": db_fetchrow, "db_fetchval": db_fetchval, "db_executemany": db_executemany,
    "_chain_context": _chain_context, "_trace_ctx": _trace_ctx, "_request_meta": _request_meta,
    "_write_assertion": _write_assertion, "_write_error_bus": _write_error_bus,
    "_emit_span": _emit_span, "_platform_call": _repair_platform_call,
    "_job_checkpoint": _job_checkpoint, "JobPaused": JobPaused,
}


# ============================================================================
# FORWARD ENGINE
# ============================================================================

_MCPDB_EXECUTE_URL: str = os.environ.get(
    "MCPDB_EXECUTE_URL",
    "https://miller-mcp-db-v3-146372550543.us-central1.run.app/execute",
)
_MCPDB_AUDIENCE: str = os.environ.get(
    "MCPDB_AUDIENCE",
    "https://miller-mcp-db-v3-irj2rlhsea-uc.a.run.app",
)
_METADATA_IDENTITY_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/"
    "service-accounts/default/identity?audience={audience}&format=full"
)
_oidc_cache: dict = {"token": None, "expires_at": 0.0}
# ── Layer 4: OIDC self-healing ────────────────────────────────────────────────
# Tracks consecutive 401s from mcpdb. At _OIDC_HEAL_THRESHOLD, the gateway
# resets _MCPDB_AUDIENCE to the base URL derived from _MCPDB_EXECUTE_URL,
# clears the token cache, and fires an error_bus event. Resets to 0 on any
# successful forward. Handles audience mismatch silently within 3 requests.
_oidc_failure_count: int = 0
_OIDC_HEAL_THRESHOLD: int = 3


class _ForwardFailed(Exception):
    pass


async def _get_oidc_token() -> str:
    now = time.monotonic()
    if _oidc_cache["token"] and now < _oidc_cache["expires_at"]:
        return _oidc_cache["token"]
    url = _METADATA_IDENTITY_URL.format(audience=_MCPDB_AUDIENCE)
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(url, headers={"Metadata-Flavor": "Google"})
        resp.raise_for_status()
    token = resp.text.strip()
    try:
        import base64 as _b64
        _parts = token.split(".")
        _pad = _parts[1] + "=" * (-len(_parts[1]) % 4)
        _payload = json.loads(_b64.urlsafe_b64decode(_pad))
        _oidc_cache["token"] = token
        _oidc_cache["expires_at"] = float(_payload.get("exp", now + 3600)) - 300
    except Exception:
        _oidc_cache["token"] = token
        _oidc_cache["expires_at"] = now + 3000
    return token


async def _forward_to_mcpdb(tool_name: str, arguments: Dict[str, Any], trace_id: str) -> Any:
    """POST to miller-mcp-db-v3 /execute via OIDC. Raises _ForwardFailed on 5xx/network error."""
    token = await _get_oidc_token()
    headers: Dict[str, str] = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Caller-Tool": "mcp-gateway",
    }
    _tc = _trace_ctx.get()
    if _tc.get("trace_id") and _tc.get("span_id"):
        headers["traceparent"] = f"00-{_tc['trace_id']}-{_tc['span_id']}-01"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(95.0, connect=5.0)) as client:
            resp = await client.post(
                _MCPDB_EXECUTE_URL,
                json={"tool_name": tool_name, "arguments": arguments},
                headers=headers,
            )
    except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
        raise _ForwardFailed(f"network error: {exc}") from exc
    if resp.status_code in (502, 503, 504):
        raise _ForwardFailed(f"mcpdb returned HTTP {resp.status_code}")
    if resp.status_code == 400:
        data = resp.json()
        raise ValueError(data.get("error", f"bad request: {resp.text[:200]}"))
    if resp.status_code == 401:
        global _oidc_failure_count, _MCPDB_AUDIENCE
        _oidc_failure_count += 1
        _failures = _oidc_failure_count
        log.error(
            "gateway: OIDC 401 from mcpdb (failure %d/%d) — audience=%s tool=%s",
            _failures, _OIDC_HEAL_THRESHOLD, _MCPDB_AUDIENCE, tool_name,
            extra={"tool_name": tool_name},
        )
        if _failures >= _OIDC_HEAL_THRESHOLD:
            # ── Self-heal: derive correct audience from execute URL, bust cache ──
            _old_audience = _MCPDB_AUDIENCE
            _healed = _MCPDB_EXECUTE_URL.rsplit("/execute", 1)[0].rstrip("/")
            _MCPDB_AUDIENCE = _healed
            _oidc_cache["token"] = None
            _oidc_cache["expires_at"] = 0.0
            _oidc_failure_count = 0
            log.critical(
                "gateway: OIDC self-heal fired — audience reset %s → %s, token cache cleared",
                _old_audience, _healed,
                extra={"tool_name": tool_name},
            )
            asyncio.create_task(_write_error_bus(
                source="gateway_oidc_self_heal",
                tool_name=tool_name,
                error_name="OIDCSelfHeal",
                error_msg=(
                    f"{_OIDC_HEAL_THRESHOLD} consecutive 401s — "
                    f"audience reset {_old_audience!r} → {_healed!r}, token cache cleared"
                ),
                trace_id=trace_id,
                context={
                    "old_audience":       _old_audience,
                    "new_audience":       _healed,
                    "mcpdb_execute_url":  _MCPDB_EXECUTE_URL,
                    "tool_name":          tool_name,
                    "consecutive_401s":   _failures,
                },
            ))
        raise RuntimeError(
            f"gateway OIDC token rejected by mcpdb "
            f"(consecutive failures: {_failures}, audience: {_MCPDB_AUDIENCE})"
        )
    resp.raise_for_status()
    # ── Success: reset OIDC failure counter ───────────────────────────────────
    if _oidc_failure_count > 0:
        _oidc_failure_count = 0
    data = resp.json()
    return data.get("result", data)


async def _execute_repair(
    tool_name: str, arguments: Dict[str, Any], trace_id: str, row: asyncpg.Record,
) -> Any:
    """Minimal local execution — repair tools only (tool_status='repair' enforced by caller)."""
    code = row["code"]; schema = row["input_schema"]; version = row["version"]
    arguments = coerce_args(arguments, schema)
    cache_entry = _CODE_CACHE.get(tool_name)
    if cache_entry is None or cache_entry[0] != version:
        try:
            compiled = compile(code, f"<tool:{tool_name}>", "exec")
            _CODE_CACHE[tool_name] = (version, compiled)
        except SyntaxError as exc:
            raise RuntimeError(f"[repair] Tool '{tool_name}' syntax error: {exc}") from exc
    else:
        compiled = cache_entry[1]
    _sk = arguments.get("session_key", "") if isinstance(arguments, dict) else ""
    _audit_pool = _AuditPool(db_pool, tool_name, "ai", _sk)
    scope: Dict[str, Any] = {
        **_TOOL_GLOBALS, "db_pool": _audit_pool,
        "_caller_tool": None, "args": arguments, "_is_degraded": False,
    }
    try:
        exec(compiled, scope)
    except SyntaxError as exc:
        raise RuntimeError(f"[repair] Tool '{tool_name}' syntax error: {exc}") from exc
    run_fn = scope.get("run")
    if run_fn is None:
        raise RuntimeError(f"[repair] Tool '{tool_name}' must define async def run(args)")
    if not inspect.iscoroutinefunction(run_fn):
        raise RuntimeError(f"[repair] Tool '{tool_name}': run must be async")
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
    _chain = {k: arguments[k] for k in _CHAIN_KEYS if isinstance(arguments, dict) and arguments.get(k)}
    _chain_token = _chain_context.set(_chain) if _chain else None
    try:
        result = await asyncio.wait_for(run_fn(arguments), timeout=_timeout_sec)
        asyncio.create_task(_assert_output(result, row.get("output_schema"), tool_name, trace_id))
        if isinstance(result, dict) and "trace_id" not in result:
            result["trace_id"] = trace_id
    except asyncio.TimeoutError:
        status = "error"; error_type = "TimeoutError"
        raise RuntimeError(f"[repair] Tool '{tool_name}' timed out after {_timeout_sec}s.")
    except Exception as e:
        status = "error"; error_type = type(e).__name__
        import traceback as _tb
        await _write_error_bus(
            "gateway_repair_dispatch", tool_name=tool_name,
            error_name=type(e).__name__, error_msg=str(e)[:500],
            stack_trace=_tb.format_exc()[:5000], trace_id=trace_id,
            context={"version": version, "mode": "repair"},
        )
        raise
    finally:
        if _chain_token is not None: _chain_context.reset(_chain_token)
        duration_ms = int((time.monotonic() - t0) * 1000)
        log.info("[repair] Tool '%s' %s (%dms)", tool_name, status.upper(), duration_ms,
                 extra={"trace_id": trace_id, "tool_name": tool_name, "duration_ms": duration_ms})
        _tc = _trace_ctx.get()
        if _tc.get("trace_id") and db_pool:
            asyncio.create_task(_emit_span(
                trace_id=_tc["trace_id"], span_id=_tc.get("span_id") or os.urandom(8).hex(),
                parent_span_id=_tc.get("parent_span_id"), service="gateway_repair",
                operation="repair_dispatch", tool_name=tool_name, duration_ms=duration_ms,
                status=status, error_type=error_type, attributes={"version": version, "mode": "repair"},
            ))
    if isinstance(result, dict) and row.get("operational_intel"):
        _oi = row["operational_intel"]
        result["_intel"] = json.loads(_oi) if isinstance(_oi, str) else _oi
    return result


# ============================================================================
# _dispatch — OIDC FORWARD + REPAIR FALLBACK
# ============================================================================

async def _dispatch(tool_name: str, arguments: Dict[str, Any], trace_id: str | None = None) -> Any:
    if trace_id is None:
        trace_id = str(uuid.uuid4())
    _dispatch_span_id = os.urandom(8).hex()
    _existing_tc = _trace_ctx.get()
    _trace_token = None
    if not _existing_tc.get("trace_id"):
        _trace_token = _trace_ctx.set({"trace_id": trace_id, "span_id": _dispatch_span_id, "parent_span_id": None})
    else:
        _trace_token = _trace_ctx.set({"trace_id": _existing_tc["trace_id"], "span_id": _dispatch_span_id, "parent_span_id": _existing_tc.get("span_id")})
    try:
        # Normal path
        try:
            return await _forward_to_mcpdb(tool_name, arguments, trace_id)
        except _ForwardFailed as fwd_exc:
            log.warning("gateway: forward failed '%s': %s", tool_name, fwd_exc, extra={"tool_name": tool_name})
            asyncio.create_task(_write_error_bus(
                "gateway_forward_failed", tool_name=tool_name, error_name="ForwardFailed",
                error_msg=str(fwd_exc)[:500], trace_id=trace_id,
                context={"mcpdb_url": _MCPDB_EXECUTE_URL},
            ))
        # Repair path
        if not db_pool:
            raise RuntimeError("mcpdb unreachable and gateway DB pool unavailable.")
        row = await db_pool.fetchrow(
            "SELECT code, input_schema, output_schema, operational_intel, version, tool_status "
            "FROM tool_registry WHERE name = $1 AND enabled = TRUE",
            tool_name,
        )
        if row is None:
            async with db_pool.acquire() as conn:
                count = await conn.fetchval("SELECT COUNT(*) FROM tool_registry WHERE enabled = TRUE")
            raise ValueError(f"Tool '{tool_name}' not found in registry ({count} tools).")
        if row["tool_status"] != "repair":
            raise RuntimeError(
                f"mcpdb unreachable and '{tool_name}' (status='{row['tool_status']}') "
                f"is not tagged for repair fallback. Only tool_status='repair' tools run locally."
            )
        log.info("gateway: repair fallback '%s'", tool_name, extra={"tool_name": tool_name, "mcpdb_status": "down"})
        return await _execute_repair(tool_name, arguments, trace_id, row)
    finally:
        if _trace_token is not None:
            _trace_ctx.reset(_trace_token)


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
    log.info("MCP Gateway v5 starting (S1038 forward+repair)...")
    db_pool = await asyncpg.create_pool(
        DATABASE_URL, min_size=POOL_MIN, max_size=POOL_MAX,
        command_timeout=TOOL_TIMEOUT, statement_cache_size=0,
    )
    await load_jwt_secret(db_pool)
    _TOOL_GLOBALS["db_pool"] = db_pool
    tool_count = await db_pool.fetchval("SELECT count(*) FROM tool_registry WHERE enabled = true")
    repair_count = await db_pool.fetchval(
        "SELECT count(*) FROM tool_registry WHERE enabled = true AND tool_status = 'repair'"
    )
    log.info("Pool ready — %d tools (%d repair-tagged)", tool_count, repair_count,
             extra={"tool_count": int(tool_count)})
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
                log.info("Shutdown: draining %d requests...", _active_requests)
                for _ in range(80):
                    if _active_requests == 0: break
                    await asyncio.sleep(0.1)
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
_mcp_sub_app = mcp.streamable_http_app()


@mcp.tool()
async def meta_tool(tool_name: str, arguments: Any = None) -> Any:
    """Execute any tool in the registry. Internal tools blocked from MCP."""
    # Guard: catch MCP framework self-injection quirk
    if tool_name in ("meta_tool", "ping", "gateway_status", ""):
        return {"status": "error", "error": (
            f"'{tool_name}' is a native gateway tool. Provide a tool_registry tool name."
        )}
    if db_pool:
        tool_status = await db_pool.fetchval(
            "SELECT tool_status FROM tool_registry WHERE name=$1 AND enabled=TRUE", tool_name,
        )
        if tool_status == "internal":
            return {"status": "error", "error": f"Tool '{tool_name}' is internal — MCP blocked."}
    if isinstance(arguments, str):
        try: arguments = json.loads(arguments)
        except (json.JSONDecodeError, TypeError): arguments = {}
    if not isinstance(arguments, dict): arguments = {}
    _t_trace_id = uuid.uuid4().hex
    _t_span_id  = os.urandom(8).hex()
    _t_tok = _trace_ctx.set({"trace_id": _t_trace_id, "span_id": _t_span_id, "parent_span_id": None})
    try:
        return await _dispatch(tool_name, arguments, trace_id=_t_trace_id)
    finally:
        _trace_ctx.reset(_t_tok)


@mcp.tool()
def ping() -> str:
    """Returns pong — verifies MCP gateway connectivity."""
    return "pong"


@mcp.tool()
async def gateway_status() -> dict:
    """Live health: DB, tool count, mcpdb reachability, repair tool count."""
    info: Dict[str, Any] = {
        "gateway": "MCP Gateway v5 — S1038 Forward+Repair",
        "strategy": "OIDC forward to mcpdb; repair fallback for tool_status='repair'",
        "mcpdb_execute_url": _MCPDB_EXECUTE_URL,
        "mcpdb_audience": _MCPDB_AUDIENCE,
        "timeout_s": TOOL_TIMEOUT, "pool": f"{POOL_MIN}-{POOL_MAX}",
        "compile_cache_size": len(_CODE_CACHE), "active_requests": _active_requests,
    }
    try:
        token = await _get_oidc_token()
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as client:
            resp = await client.get(
                _MCPDB_EXECUTE_URL.replace("/execute", "/health"),
                headers={"Authorization": f"Bearer {token}"},
            )
        info["mcpdb_status"] = "reachable" if resp.status_code < 500 else f"http_{resp.status_code}"
        info["mcpdb_http_status"] = resp.status_code
    except _ForwardFailed as e:
        info["mcpdb_status"] = f"unreachable: {e}"
    except Exception as e:
        info["mcpdb_status"] = f"probe_error: {type(e).__name__}: {str(e)[:100]}"
    if os.path.isdir(SECRETS_DIR):
        info["secrets"] = len(os.listdir(SECRETS_DIR))
    if db_pool:
        try:
            t0 = time.monotonic()
            n = await db_pool.fetchval("SELECT count(*) FROM tool_registry WHERE enabled = true")
            r = await db_pool.fetchval(
                "SELECT count(*) FROM tool_registry WHERE enabled = true AND tool_status = 'repair'"
            )
            info["db"] = "connected"
            info["enabled_tools"] = int(n)
            info["repair_tools"] = int(r)
            info["db_latency_ms"] = round((time.monotonic() - t0) * 1000, 1)
        except Exception as exc:
            info["db"] = f"error: {exc}"
    return info


app = FastAPI(
    title="MillerMCPGateway",
    description="Miller IQ MCP Gateway v5 — OIDC forward + repair fallback",
    version="5.0.0", lifespan=lifespan,
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
        "status": "ok" if db_ok else "degraded", "service": "miller-mcp-gateway",
        "version": "5.0.0", "db": "connected" if db_ok else "unreachable",
        "db_latency_ms": db_latency, "tool_count": tool_count,
        "compile_cache_size": len(_CODE_CACHE), "active_requests": _active_requests,
        "strategy": "forward+repair",
    }


# ============================================================================
# GCS STAGE UPLOAD — S1042 Chat-drop-to-CloudTask bridge
#
# bash_tool reads /mnt/user-data/uploads/{filename} → POST raw bytes here.
# Gateway has GCP metadata server access; bash_tool does not.
# Pure relay: zero byte inspection, zero transformation.
# Returns gs:// URL → caller fires load_reference_spreadsheet via fire_cloud_task.
# ============================================================================

_PLATFORM_API_KEY = os.environ.get("PLATFORM_API_KEY", "miller-techstack-2026")
_GCS_UPLOAD_URL   = "https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o?uploadType=media&name={name}"
_GCS_TOKEN_URL    = ("http://metadata.google.internal/computeMetadata/v1/instance/"
                     "service-accounts/default/token")


@app.post("/upload/gcs-stage")
async def gcs_stage(request: Request):
    """
    S1042 — Raw file bytes passthrough: chat upload → GCS.

    Called by bash_tool after reading /mnt/user-data/uploads/{filename}.
    Gateway holds GCP credentials; bash_tool does not.
    Pure relay: zero byte inspection, zero transformation.

    Request headers:
        X-API-Key    (required) — platform API key
        X-Filename   (required) — original filename (e.g. ZIP_COUNTY_122025.xlsx)
        X-GCS-Path   (required) — GCS object path (e.g. reference-data/hud/ZIP_COUNTY_122025.xlsx)
        X-GCS-Bucket (optional) — GCS bucket (default: miller-platform-assets)
        Content-Type (optional) — passed through to GCS

    Returns:
        {status, gcs_url, size_bytes, filename, bucket, gcs_path, trace_id}

    Full chat-drop flow:
        bash_tool reads /mnt/user-data/uploads/{filename}
        POST /upload/gcs-stage → {gcs_url}
        load_reference_spreadsheet(gcs_url, dry_run=True) → validate
        fire_cloud_task(tool_name='load_reference_spreadsheet', args={gcs_url, ...}) → job_id
    """
    import urllib.parse as _up
from miller_jwt_gateway import load_jwt_secret, build_auth_headers

    trace_id = getattr(request.state, "trace_id", None) or str(uuid.uuid4())

    # ── Auth ─────────────────────────────────────────────────────────────────
    api_key = request.headers.get("X-API-Key", "")
    if api_key != _PLATFORM_API_KEY:
        log.warning("gcs_stage: unauthorized attempt", extra={"trace_id": trace_id})
        return JSONResponse({"error": "unauthorized", "trace_id": trace_id}, status_code=401)

    # ── Headers ──────────────────────────────────────────────────────────────
    filename   = request.headers.get("X-Filename", "").strip()
    gcs_path   = request.headers.get("X-GCS-Path", "").strip()
    bucket     = request.headers.get("X-GCS-Bucket", "miller-platform-assets").strip()
    media_type = request.headers.get("Content-Type", "application/octet-stream")

    if not filename:
        return JSONResponse({"error": "X-Filename header is required", "trace_id": trace_id}, status_code=400)
    if not gcs_path:
        gcs_path = f"uploads/{filename}"

    # ── Read body ─────────────────────────────────────────────────────────────
    try:
        raw_bytes = await request.body()
    except Exception as e:
        return JSONResponse({"error": f"Failed to read body: {e}", "trace_id": trace_id}, status_code=400)

    if not raw_bytes:
        return JSONResponse({"error": "Empty body — no bytes received", "trace_id": trace_id}, status_code=400)

    size_bytes = len(raw_bytes)

    # ── GCP token ─────────────────────────────────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=5.0) as _tc:
            _tok = await _tc.get(_GCS_TOKEN_URL, headers={"Metadata-Flavor": "Google"})
            _tok.raise_for_status()
        gcp_token = _tok.json()["access_token"]
    except Exception as e:
        log.error("gcs_stage: GCP token failed: %s", e, extra={"trace_id": trace_id})
        asyncio.create_task(_write_error_bus(
            "gcs_stage", error_name="GCPTokenError",
            error_msg=str(e)[:300], trace_id=trace_id,
        ))
        return JSONResponse({"error": f"GCP auth failed: {e}", "trace_id": trace_id}, status_code=500)

    # ── Upload to GCS — pure passthrough ──────────────────────────────────────
    encoded_path = _up.quote(gcs_path, safe="")
    upload_url   = _GCS_UPLOAD_URL.format(bucket=bucket, name=encoded_path)
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(120.0, connect=10.0)) as _gc:
            _resp = await _gc.post(
                upload_url,
                content=raw_bytes,
                headers={
                    "Authorization": f"Bearer {gcp_token}",
                    "Content-Type":  media_type,
                    "Content-Length": str(size_bytes),
                },
            )
        if _resp.status_code not in (200, 201):
            err = f"GCS upload HTTP {_resp.status_code}: {_resp.text[:200]}"
            log.error("gcs_stage: %s", err, extra={"trace_id": trace_id})
            asyncio.create_task(_write_error_bus(
                "gcs_stage", error_name="GCSUploadError", error_msg=err, trace_id=trace_id,
                context={"bucket": bucket, "gcs_path": gcs_path, "size_bytes": size_bytes},
            ))
            return JSONResponse({"error": err, "trace_id": trace_id}, status_code=502)
    except Exception as e:
        log.error("gcs_stage: upload exception: %s", e, extra={"trace_id": trace_id})
        asyncio.create_task(_write_error_bus(
            "gcs_stage", error_name="GCSUploadException",
            error_msg=str(e)[:300], trace_id=trace_id,
        ))
        return JSONResponse({"error": f"GCS upload failed: {e}", "trace_id": trace_id}, status_code=500)

    gcs_url = f"gs://{bucket}/{gcs_path}"
    log.info(
        "gcs_stage: %s → %s (%d bytes)",
        filename, gcs_url, size_bytes,
        extra={"trace_id": trace_id},
    )
    return JSONResponse({
        "status":     "ok",
        "gcs_url":    gcs_url,
        "size_bytes": size_bytes,
        "filename":   filename,
        "bucket":     bucket,
        "gcs_path":   gcs_path,
        "trace_id":   trace_id,
    })


app.mount("/", _mcp_sub_app)