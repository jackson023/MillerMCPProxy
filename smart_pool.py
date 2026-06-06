"""
    Miller IQ Platform — SmartPool v1

    Drop-in replacement for asyncpg.Pool.
    Normal mode:   AlloyDB handles everything (zero overhead).
    Degraded mode: All reads/writes route to BigQuery transparently.
    Recovery:      POST /api/alloydb-recovered verifies AlloyDB and switches back.

    Session 4 — BigQuery SmartPool DR stack.
    """
import asyncio
import json
import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, date, timezone

import httpx
import sqlglot

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────
_BQ_PROJECT       = 'miller-iq-platform'
_BQ_DATASET       = 'millerplatformiq'
_BQ_QUERIES_URL   = f'https://bigquery.googleapis.com/bigquery/v2/projects/{_BQ_PROJECT}/queries'
_GCS_BUCKET       = 'miller-iq-backups'
_GCS_FLAG_PATH    = 'degraded_mode.json'
FAILOVER_THRESHOLD = 3   # consecutive acquire() failures before entering degraded mode
ACQUIRE_TIMEOUT_S  = 2   # seconds to wait for AlloyDB connection before failing

# ── Shared OAuth token (module-level, thread-safe via asyncio.Lock) ───────────
_token_lock: asyncio.Lock | None = None
_cached_token: str | None = None
_token_expires: float = 0

async def _get_token() -> str:
    global _token_lock, _cached_token, _token_expires
    if _token_lock is None:
        _token_lock = asyncio.Lock()
    async with _token_lock:
        if _cached_token and time.time() < _token_expires:
            return _cached_token
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
                headers={'Metadata-Flavor': 'Google'}
            )
        d = r.json()
        _cached_token = d['access_token']
        _token_expires = time.time() + min(d.get('expires_in', 3600), 3000)
        return _cached_token

# ── SQL translation (read path) ──────────────────────────────────────────────

def _convert_params(sql: str) -> str:
    return re.sub(r'\$(\d+)', lambda m: f'@p{m.group(1)}', sql)

def _prefix_tables(sql: str) -> str:
    try:
        ast = sqlglot.parse_one(sql, read='postgres')
        for node in ast.walk():
            if isinstance(node, sqlglot.exp.Table) and not node.db and not node.catalog:
                node.set('db', sqlglot.exp.Identifier(this=_BQ_DATASET, quoted=True))
                node.set('catalog', sqlglot.exp.Identifier(this=_BQ_PROJECT, quoted=True))
        return ast.sql(dialect='bigquery')
    except Exception:
        def _pfx(m):
            kw, name = m.group(1), m.group(2)
            return f'{kw} `{_BQ_PROJECT}`.`{_BQ_DATASET}`.{name}' if not name.startswith("'") else m.group(0)
        return re.sub(r'\b(FROM|JOIN)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', _pfx, sql, flags=re.IGNORECASE)

def _args_to_bq_params(args: tuple) -> list:
    params = []
    for i, val in enumerate(args, 1):
        n = f'p{i}'
        if isinstance(val, bool):
            params.append({'name': n, 'parameterType': {'type': 'BOOL'}, 'parameterValue': {'value': str(val).lower()}})
        elif isinstance(val, int):
            params.append({'name': n, 'parameterType': {'type': 'INT64'}, 'parameterValue': {'value': str(val)}})
        elif isinstance(val, float):
            params.append({'name': n, 'parameterType': {'type': 'FLOAT64'}, 'parameterValue': {'value': str(val)}})
        elif isinstance(val, datetime):
            params.append({'name': n, 'parameterType': {'type': 'TIMESTAMP'}, 'parameterValue': {'value': val.isoformat()}})
        elif isinstance(val, date):
            params.append({'name': n, 'parameterType': {'type': 'DATE'}, 'parameterValue': {'value': val.isoformat()}})
        elif val is None:
            params.append({'name': n, 'parameterType': {'type': 'STRING'}, 'parameterValue': {'value': None}})
        else:
            params.append({'name': n, 'parameterType': {'type': 'STRING'}, 'parameterValue': {'value': str(val)}})
    return params

# ── DML parsing (write path) ─────────────────────────────────────────────────

def _resolve_val(expr, args):
    if isinstance(expr, sqlglot.exp.Parameter):
        idx = int(expr.name) - 1
        return args[idx] if idx < len(args) else None
    if isinstance(expr, sqlglot.exp.Cast): return _resolve_val(expr.this, args)
    if isinstance(expr, sqlglot.exp.Literal): return int(expr.name) if expr.is_number else expr.name
    if isinstance(expr, sqlglot.exp.Boolean): return expr.args.get('this', False)
    if isinstance(expr, sqlglot.exp.Null): return None
    # Substitute SQL timestamp functions with real current timestamp (bug #3970)
    # BQ insertAll does not evaluate SQL functions — needs literal ISO string
    if isinstance(expr, (sqlglot.exp.CurrentTimestamp, sqlglot.exp.CurrentDatetime,
                          sqlglot.exp.CurrentDate)):
        return datetime.now(timezone.utc).isoformat()
    if isinstance(expr, sqlglot.exp.Anonymous) and expr.name.upper() in (
            'NOW', 'CURRENT_TIMESTAMP', 'CURRENT_TIME'):
        return datetime.now(timezone.utc).isoformat()
    return expr.sql()

def _parse_write(pg_sql: str, args: tuple) -> dict:
    sql = re.sub(r'\bRETURNING\b.*$', '', pg_sql, flags=re.IGNORECASE | re.DOTALL).strip()
    sql = re.sub(r'\bON CONFLICT\b.*$', '', sql, flags=re.IGNORECASE | re.DOTALL).strip()
    ast = sqlglot.parse_one(sql, read='postgres')
    def _eq_map(node):
        return {eq.args['this'].name: _resolve_val(eq.args['expression'], args)
                for eq in node.find_all(sqlglot.exp.EQ)
                if isinstance(eq.args.get('this'), sqlglot.exp.Column)}
    if isinstance(ast, sqlglot.exp.Insert):
        sn = ast.args['this']
        cols = [e.name for e in sn.expressions]
        vals = ast.args['expression'].expressions[0].expressions
        return {'operation': 'INSERT', 'table': sn.this.name,
                'row': {c: _resolve_val(v, args) for c, v in zip(cols, vals)}}
    elif isinstance(ast, sqlglot.exp.Update):
        return {'operation': 'UPDATE', 'table': ast.find(sqlglot.exp.Table).name, 'row': _eq_map(ast)}
    elif isinstance(ast, sqlglot.exp.Delete):
        tbl = ast.find(sqlglot.exp.Table)
        return {'operation': 'DELETE', 'table': tbl.name if tbl else 'unknown', 'row': _eq_map(ast)}
    raise ValueError(f'Unsupported DML: {pg_sql[:80]}')

def _tag_for_replay(parsed: dict) -> dict:
    """Add _degraded_* metadata columns for Session 5 bq_replay."""
    row = dict(parsed['row'])
    if 'genie_id' not in row:
        row['genie_id'] = str(uuid.uuid4())
    row['_degraded_write_at'] = datetime.now(timezone.utc).isoformat()
    row['_degraded_operation'] = parsed['operation']
    row['_degraded_replayed'] = False
    return row

def _clean_for_insertall(row: dict) -> dict:
    return {k: (v.isoformat() if isinstance(v, datetime) else v)
            for k, v in row.items() if v is not None}

# ── BigQueryRecord ────────────────────────────────────────────────────────────────

class BigQueryRecord:
    """asyncpg.Record-compatible wrapper for BigQuery row dicts."""
    __slots__ = ('_data', '_fields')
    def __init__(self, data: dict, fields: list):
        self._data = data; self._fields = list(fields)
    def __getitem__(self, key):
        return self._data[self._fields[key]] if isinstance(key, int) else self._data[key]
    def __contains__(self, key): return key in self._data
    def __iter__(self): return iter(self._fields)
    def __len__(self): return len(self._fields)
    def __repr__(self): return f'<BigQueryRecord {dict(self.items())}>'
    def get(self, key, default=None): return self._data.get(key, default)
    def keys(self): return self._fields
    def values(self): return [self._data[f] for f in self._fields]
    def items(self): return [(f, self._data[f]) for f in self._fields]

# ── BigQueryConnection ──────────────────────────────────────────────────────────

class BigQueryConnection:
    """asyncpg Connection-compatible, backed by BQ Jobs API + tabledata.insertAll."""
    _INT_T   = {'INTEGER','INT64','INT','SMALLINT','BIGINT','TINYINT','BYTEINT'}
    _FLOAT_T = {'FLOAT','FLOAT64','NUMERIC','BIGNUMERIC','DECIMAL','BIGDECIMAL'}
    _BOOL_T  = {'BOOLEAN','BOOL'}

    def __init__(self, token: str):
        self._hdrs = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    async def _run_query(self, pg_sql: str, args: tuple) -> dict:
        bq_sql = _prefix_tables(_convert_params(pg_sql))
        bq_params = _args_to_bq_params(args)
        body = {
            'query': bq_sql, 'useLegacySql': False,
            'queryParameters': bq_params,
            'parameterMode': 'NAMED' if bq_params else 'POSITIONAL',
            'location': 'us-central1', 'timeoutMs': 30000
        }
        async with httpx.AsyncClient(timeout=35) as c:
            r = await c.post(_BQ_QUERIES_URL, headers=self._hdrs, json=body)
        if r.status_code != 200:
            raise Exception(f'BQ query error {r.status_code}: {r.text[:200]}')
        return r.json()

    def _parse_rows(self, result: dict) -> list:
        schema = result.get('schema', {}).get('fields', [])
        fields = [f['name'] for f in schema]
        types  = [f.get('type', 'STRING').upper() for f in schema]
        def _coerce(val, typ):
            if val is None: return None
            if typ in self._INT_T:
                try: return int(val)
                except Exception: return val
            if typ in self._FLOAT_T:
                try: return float(val)
                except Exception: return val
            if typ in self._BOOL_T:
                return val.lower() == 'true' if isinstance(val, str) else bool(val)
            return val
        rows = []
        for row in result.get('rows', []):
            cells = row.get('f', [])
            data = {fields[i]: _coerce(cells[i].get('v'), types[i]) for i in range(len(fields))}
            rows.append(BigQueryRecord(data, fields))
        return rows

    async def _write_dml(self, pg_sql: str, args: tuple) -> str:
        parsed = _parse_write(pg_sql, args)
        row    = _tag_for_replay(parsed)
        url    = (f'https://bigquery.googleapis.com/bigquery/v2/projects/{_BQ_PROJECT}'
                  f'/datasets/{_BQ_DATASET}/tables/{parsed['table']}/insertAll')
        body   = {'rows': [{'insertId': f'sp-{row['genie_id']}-{parsed['operation'].lower()}',
                               'json': _clean_for_insertall(row)}],
                   'skipInvalidRows': False, 'ignoreUnknownValues': False}
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(url, headers=self._hdrs, json=body)
        if r.status_code != 200:
            raise Exception(f'insertAll {r.status_code}: {r.text[:200]}')
        errs = r.json().get('insertErrors', [])
        if errs:
            raise Exception(f'insertAll row errors: {json.dumps(errs)[:300]}')
        logger.info('SmartPool/BQ: %s written to %s (degraded mode)', parsed['operation'], parsed['table'])
        return f'{parsed['operation']} 1'

    async def fetch(self, query: str, *args) -> list:
        return self._parse_rows(await self._run_query(query, args))

    async def fetchrow(self, query: str, *args):
        rows = self._parse_rows(await self._run_query(query, args))
        return rows[0] if rows else None

    async def fetchval(self, query: str, *args, column: int = 0):
        rows = self._parse_rows(await self._run_query(query, args))
        return rows[0][column] if rows else None

    async def execute(self, query: str, *args) -> str:
        sql = query.strip().upper()
        if sql.startswith('SELECT') or sql.startswith('WITH'):
            await self._run_query(query, args)
            return 'SELECT 1'
        return await self._write_dml(query, args)

    async def executemany(self, query: str, args_list: list) -> str:
        results = await asyncio.gather(*[self.execute(query, *a) for a in args_list])
        op = results[0].split()[0] if results else 'INSERT'
        return f'{op} {len(results)}'

    @asynccontextmanager
    async def transaction(self):
        logger.info('SmartPool/BQ: transaction() is a no-op in degraded mode')
        yield self

# ── BigQueryPool ────────────────────────────────────────────────────────────────────

class BigQueryPool:
    """asyncpg Pool-compatible interface backed by BigQuery. SmartPool uses this in degraded mode."""

    @asynccontextmanager
    async def acquire(self):
        yield BigQueryConnection(await _get_token())

    async def fetchval(self, query: str, *args, column: int = 0):
        async with self.acquire() as c: return await c.fetchval(query, *args, column=column)
    async def fetchrow(self, query: str, *args):
        async with self.acquire() as c: return await c.fetchrow(query, *args)
    async def fetch(self, query: str, *args):
        async with self.acquire() as c: return await c.fetch(query, *args)
    async def execute(self, query: str, *args):
        async with self.acquire() as c: return await c.execute(query, *args)

# ── SmartPool ───────────────────────────────────────────────────────────────────────

class SmartPool:
    """
    Drop-in asyncpg.Pool replacement with BigQuery hot-standby.

    Normal mode:   delegates everything to AlloyDB pool (zero overhead).
    Degraded mode: after FAILOVER_THRESHOLD consecutive failures, switches
                   all operations to BigQueryPool transparently.
    Recovery:      POST /api/alloydb-recovered → _exit_degraded() → bq_replay (Session 5).
    """

    def __init__(self, alloydb_pool, bq_pool: BigQueryPool):
        self._alloydb    = alloydb_pool
        self._bq         = bq_pool
        self._degraded   = False
        self._lock       = asyncio.Lock()
        self._failcount  = 0

    # ── Degraded mode transitions ───────────────────────────────────────────────

    async def _maybe_failover(self, exc: Exception):
        async with self._lock:
            if self._degraded:
                return
            self._failcount += 1
            logger.warning('SmartPool: AlloyDB failure %d/%d — %s',
                           self._failcount, FAILOVER_THRESHOLD, exc)
            if self._failcount >= FAILOVER_THRESHOLD:
                await self._enter_degraded()

    async def _enter_degraded(self):
        self._degraded  = True
        self._failcount = 0
        logger.critical(
            'SmartPool: *** DEGRADED MODE *** AlloyDB unreachable — switching all operations to BigQuery'
        )
        try:
            token = await _get_token()
            flag  = json.dumps({'degraded': True,
                                'entered_at': datetime.now(timezone.utc).isoformat()})
            async with httpx.AsyncClient(timeout=10) as c:
                await c.post(
                    f'https://storage.googleapis.com/upload/storage/v1/b/{_GCS_BUCKET}/o',
                    params={'uploadType': 'media', 'name': _GCS_FLAG_PATH},
                    content=flag.encode(),
                    headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
                )
            logger.info('SmartPool: GCS degraded flag written — other replicas will detect on startup')
        except Exception as e:
            logger.error('SmartPool: GCS flag write failed (non-blocking): %s', e)

    async def _exit_degraded(self):
        """Called by /api/alloydb-recovered. Switches back to AlloyDB."""
        async with self._lock:
            if not self._degraded:
                return
            self._degraded  = False
            self._failcount = 0
        logger.info('SmartPool: *** RECOVERED *** switching back to AlloyDB'
                    '  Session 5 bq_replay will replay degraded-mode writes.')
        try:
            token = await _get_token()
            async with httpx.AsyncClient(timeout=10) as c:
                await c.delete(
                    f'https://storage.googleapis.com/storage/v1/b/{_GCS_BUCKET}/o/{_GCS_FLAG_PATH}',
                    headers={'Authorization': f'Bearer {token}'}
                )
            logger.info('SmartPool: GCS degraded flag cleared')
        except Exception as e:
            logger.warning('SmartPool: GCS flag delete failed (non-blocking): %s', e)

    async def check_degraded_flag(self):
        """Called on startup — if GCS flag exists, enter degraded mode immediately."""
        try:
            token = await _get_token()
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(
                    f'https://storage.googleapis.com/storage/v1/b/{_GCS_BUCKET}/o/{_GCS_FLAG_PATH}',
                    headers={'Authorization': f'Bearer {token}'},
                    params={'alt': 'media'}
                )
            if r.status_code == 200:
                flag = r.json()
                logger.critical(
                    'SmartPool: GCS degraded flag found (entered_at=%s) — starting in DEGRADED MODE',
                    flag.get('entered_at')
                )
                self._degraded = True
            else:
                logger.info('SmartPool: no degraded flag — starting in NORMAL mode')
        except Exception as e:
            logger.debug('SmartPool: degraded flag check failed (assuming normal): %s', e)

    # ── asyncpg Pool interface ──────────────────────────────────────────────────

    @asynccontextmanager
    async def acquire(self):
        if self._degraded:
            async with self._bq.acquire() as conn:
                yield conn
            return
        try:
            async with asyncio.timeout(ACQUIRE_TIMEOUT_S):
                async with self._alloydb.acquire() as conn:
                    self._failcount = 0   # reset on clean acquire
                    yield conn
        except Exception as exc:
            await self._maybe_failover(exc)
            if self._degraded:
                async with self._bq.acquire() as conn:
                    yield conn
            else:
                raise

    async def fetchval(self, query: str, *args, column: int = 0):
        if self._degraded:
            return await self._bq.fetchval(query, *args, column=column)
        try:
            return await self._alloydb.fetchval(query, *args)
        except Exception as exc:
            await self._maybe_failover(exc)
            if self._degraded: return await self._bq.fetchval(query, *args, column=column)
            raise

    async def fetchrow(self, query: str, *args):
        if self._degraded:
            return await self._bq.fetchrow(query, *args)
        try:
            return await self._alloydb.fetchrow(query, *args)
        except Exception as exc:
            await self._maybe_failover(exc)
            if self._degraded: return await self._bq.fetchrow(query, *args)
            raise

    async def fetch(self, query: str, *args):
        if self._degraded:
            return await self._bq.fetch(query, *args)
        try:
            return await self._alloydb.fetch(query, *args)
        except Exception as exc:
            await self._maybe_failover(exc)
            if self._degraded: return await self._bq.fetch(query, *args)
            raise

    async def execute(self, query: str, *args):
        if self._degraded:
            return await self._bq.execute(query, *args)
        try:
            return await self._alloydb.execute(query, *args)
        except Exception as exc:
            await self._maybe_failover(exc)
            if self._degraded: return await self._bq.execute(query, *args)
            raise

    async def close(self):
        """Shutdown: close AlloyDB pool. BigQueryPool is stateless."""
        await self._alloydb.close()
