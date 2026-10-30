"""work_ticket.py -- [decision] #51749 work tickets, Phase 1 (SHADOW: counts, never blocks).

A work ticket is the trace id that starts at an entry point (HTTP request, Cloud Task delivery, job start, boot
loop) and travels with the work through every hand-off. Every point where compute is GRANTED calls grant():
  db_checkout   a pooled database connection is handed out (smart_pool_checkout_setup / gcloud-runner checkout)
  db_connect    a direct database connection is opened (process-wide asyncpg.connect / create_pool wrapper)
  cloud_task / crj / ai / runner / http   an outbound HTTP request (classified by destination)
grant() reads the current ticket through the reader the runtime registers (set_reader). With a ticket the grant is
counted under site '*'; without one it is counted as a MISS under the site that asked (normalised label), so the
books show exactly where unidentified compute comes from. flush_loop() writes per-minute counts to
platform_work_ticket_grants (one upsert per minute per process); v_work_ticket_coverage is the read side.

Cost on the hot path: one reader call, one dict update under an uncontended lock. Never raises into the caller.
The same file ships in MillerMCPDB, MillerJobWorker, MillerGCloudRunner and MillerMCPProxy (the MCP gateway, which
has no database: it flushes through flush_with); only RUNTIME differs.
"""
import asyncio
import datetime
import logging
import re
import threading

logger = logging.getLogger(__name__)

RUNTIME = "db-v3"

_reader = None                 # () -> ticket str | None, registered by the runtime
_counts = {}                   # (grant_point, site) -> [n_total, n_miss]
_lock = threading.Lock()       # grants also come from worker threads (sync httpx / to_thread)
_NOISE = re.compile(r"[0-9a-f]{8,}|\d{3,}")
_AI_HOSTS = frozenset({
    "aiplatform.googleapis.com", "generativelanguage.googleapis.com", "api.anthropic.com", "api.openai.com",
})
# @pfi_exempt: code_scanner:gce_metadata_direct_fetch -- the metadata host appears only in this skip list (credential plumbing is not counted as work); nothing here fetches from it
_SKIP_HOSTS = frozenset({"metadata.google.internal", "169.254.169.254"})   # credential plumbing, not work


def set_reader(fn) -> None:
    global _reader
    _reader = fn


def current_ticket():
    try:
        return _reader() if _reader else None
    except Exception:
        return None


def _site(site) -> str:
    try:
        s = site() if callable(site) else site
    except Exception:
        s = None
    if not s:
        return "?"
    return _NOISE.sub("#", str(s))[:120]


def grant(point: str, site=None):
    """Count one compute grant at `point`. `site` (str or zero-arg callable, evaluated only on a miss) names who
    asked. Returns the ticket (or None). Never raises."""
    try:
        t = current_ticket()
        key = (point, "*") if t else (point, _site(site))
        with _lock:
            c = _counts.get(key)
            if c is None:
                c = _counts[key] = [0, 0]
            c[0] += 1
            if not t:
                c[1] += 1
        return t
    except Exception:
        return None


def http_point(host: str, path: str):
    """Grant point for an outbound HTTP request, or None for credential plumbing that is not work."""
    host = (host or "").lower()
    if host in _SKIP_HOSTS:
        return None
    if host in _AI_HOSTS:
        return "ai"
    if host == "cloudtasks.googleapis.com":
        return "cloud_task"
    if host == "run.googleapis.com" and "/jobs/" in (path or ""):
        return "crj"
    if host.startswith("miller-gcloud-runner"):
        return "runner"
    return "http"


def _drain():
    global _counts
    with _lock:
        out, _counts = _counts, {}
    return out


_UPSERT = (
    "INSERT INTO platform_work_ticket_grants (minute, runtime, grant_point, site, n_total, n_miss) "
    "SELECT $1, $2, p, s, t, m FROM unnest($3::text[], $4::text[], $5::bigint[], $6::bigint[]) AS u(p, s, t, m) "
    "ON CONFLICT (minute, runtime, grant_point, site) DO UPDATE SET "
    "n_total = platform_work_ticket_grants.n_total + EXCLUDED.n_total, "
    "n_miss = platform_work_ticket_grants.n_miss + EXCLUDED.n_miss"
)


async def flush(pool) -> int:
    async def _write(minute, runtime, points, sites, totals, misses):
        async with pool.acquire() as con:
            await con.execute(_UPSERT, minute, runtime, points, sites, totals, misses)
    return await flush_with(_write)


async def flush_with(write) -> int:
    """Drain the counts and hand them to `write(minute, runtime, points, sites, totals, misses)` (a coroutine
    function). A runtime with no database of its own (the MCP gateway) supplies a writer that posts them to db-v3.
    On any failure the counts are put back, so the next flush retries and nothing is lost."""
    rows = _drain()
    if not rows:
        return 0
    keys = list(rows)
    m = datetime.datetime.now(datetime.timezone.utc).replace(second=0, microsecond=0)
    try:
        await write(m, RUNTIME, [k[0] for k in keys], [k[1] for k in keys],
                    [rows[k][0] for k in keys], [rows[k][1] for k in keys])
    except Exception as exc:
        # put the counts back so a transient failure loses nothing; the next flush retries
        with _lock:
            for k, (t, n) in rows.items():
                c = _counts.setdefault(k, [0, 0])
                c[0] += t
                c[1] += n
        logger.warning("work_ticket flush failed (counts kept for next flush): %r", exc)
        return 0
    return len(keys)


async def flush_loop(pool_getter, every_s: float = 60.0) -> None:
    """Background flusher. pool_getter() returns the pool to write with (or None while booting)."""
    while True:
        await asyncio.sleep(every_s)
        try:
            pool = pool_getter()
            if pool is not None:
                await flush(pool)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("work_ticket flush_loop: %r", exc)


async def flush_loop_with(write, every_s: float = 60.0) -> None:
    """Background flusher for a runtime that supplies its own writer (see flush_with)."""
    while True:
        await asyncio.sleep(every_s)
        try:
            await flush_with(write)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("work_ticket flush_loop_with: %r", exc)