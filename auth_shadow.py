"""auth_shadow.py -- bug 66018: shadow evaluation of DB-held inbound keys (platform_api_keys), gateway side.

The OLD check (_key_match against the Secret Manager keys) stays authoritative. Nothing here changes a response.

The gateway holds no database connection on the request path, so the comparison runs in db-v3: rows go to the api_key
tool (op=shadow_ingest), which looks each hash up through SQL api_key_lookup(hash, scope) -- the same verdict rule the
db-v3 inline path and api_key op=verify use -- and writes ONE platform_event_log row per gateway request
(event_type 'auth.shadow', payload {route, scope, old_verdict, new_verdict, new_reason, agree, key_prefix, ...}).

Why a batch and not a forwarded header: a header only reaches db-v3 on requests the gateway forwards to a tool, so
401s (wrong or no key), /admin calls and MCP protocol messages that call no tool would never be compared, and the
one-row-per-request guarantee would not hold. A batch covers every request; the request path pays one sha256 and a
list append (microseconds). At most one flush is in flight, at most one per FLUSH_MIN_S, up to BATCH_MAX rows,
sent with the gateway's own key. A full buffer drops (counted), it never blocks.

Never raises into the caller. Never sends or logs the presented key: rows carry its sha256 only.
Standard library only.
"""
import asyncio
import datetime
import hashlib
import logging
import time

logger = logging.getLogger("miller.gateway.auth_shadow")

SERVICE = "miller-mcp-gateway"
BATCH_MAX = 200
BUFFER_CAP = 5000
FLUSH_MIN_S = 2.0

_buf: list = []
_state = {"flushing": False, "last_flush": -1e9, "sent": 0, "failed": 0, "dropped": 0, "flushes": 0}
_tasks: set = set()
_sender = {"fn": None}


def configure(sender):
    """sender: async fn(rows) -> the api_key tool result (or the gateway's {'result': ...} wrapper)."""
    _sender["fn"] = sender


def scope_for(route):
    r = str(route or "")
    if r == "/mcp" or r.startswith("/mcp/"):
        return "mcp"
    if r == "/execute":
        return "execute"
    if r.startswith("/admin"):
        return "admin"
    return "other"


def fingerprint(presented):
    if not isinstance(presented, str):
        return None
    k = presented.strip()
    if not k:
        return None
    return hashlib.sha256(k.encode("utf-8")).hexdigest()


def observe(route, presented, old_ok, ctx=None):
    """Queue one shadow comparison for this request. Never raises, never blocks, never changes the verdict."""
    try:
        if len(_buf) >= BUFFER_CAP:
            _state["dropped"] += 1
            return
        _buf.append(
            {
                "route": str(route or "")[:120],
                "scope": scope_for(route),
                "old_verdict": bool(old_ok),
                "key_sha256": fingerprint(presented),
                "ctx": ctx if isinstance(ctx, dict) else {},
                "service": SERVICE,
                "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
            }
        )
        _kick()
    except Exception as exc:
        logger.warning("auth_shadow observe failed: %s", type(exc).__name__)


_KEY_HEADERS = ("x-api-key", "x-agent-key", "x-pw-auth", "authorization")


def request_context(request):
    """Non-secret facts about the caller, for the shadow row. Never raises. No credential value, no query value:
    query parameters are recorded as NAMES only, and a key presented in the URL is flagged, not stored."""
    try:
        h = request.headers
        g = lambda k, n=200: ((h.get(k) or "")[:n]) or None
        fwd = (h.get("x-forwarded-for") or "").strip()
        qp = []
        try:
            qp = sorted({str(k)[:40] for k in request.query_params.keys()})[:10]
        except Exception:
            pass
        key_header = ""
        for k in _KEY_HEADERS:
            if (h.get(k) or "").strip():
                key_header = k
                break
        if not key_header and any(n in ("api_key", "key") for n in qp):
            key_header = "query"
        ip = (fwd.split(",")[0].strip() if fwd else "") or (getattr(getattr(request, "client", None), "host", "") or "")
        ref = (h.get("referer") or "").split("?")[0][:160] or None
        try:
            cl = int(h.get("content-length")) if h.get("content-length") else None
        except Exception:
            cl = None
        ctx = {
            "user_agent": g("user-agent"),
            "ip": ip[:64] or None,
            "forwarded_chain": fwd[:200] or None,
            "method": str(getattr(request, "method", "") or "")[:10] or None,
            "path": str(getattr(getattr(request, "url", None), "path", "") or "")[:120] or None,
            "query_params": qp,
            "key_in_query": any(n in ("api_key", "key", "token") for n in qp),
            "host": g("host", 120),
            "origin": g("origin", 120),
            "referer": ref,
            "content_type": g("content-type", 60),
            "content_length": cl,
            "mcp_protocol_version": g("mcp-protocol-version", 20),
            "mcp_session": bool(h.get("mcp-session-id")),
            "cloud_trace": g("x-cloud-trace-context", 80),
            "request_id": g("x-request-id", 64),
            "has_authorization": bool((h.get("authorization") or "").strip()),
            "has_cookie": bool(h.get("cookie")),
            "has_assertion": bool(h.get("x-miller-assertion")),
            "key_header": key_header,
        }
        return {k: v for k, v in ctx.items() if v not in (None, "")}
    except Exception:
        return {}


def _kick():
    if _state["flushing"] or _sender["fn"] is None or not _buf:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return  # no loop (import time / tests): the next request in a loop flushes
    _state["flushing"] = True
    task = loop.create_task(_flush_loop())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


def _accepted(res):
    inner = res.get("result", res) if isinstance(res, dict) else None
    return isinstance(inner, dict) and inner.get("status") == "ok", inner


async def _flush_loop():
    try:
        while _buf:
            wait = FLUSH_MIN_S - (time.monotonic() - _state["last_flush"])
            if wait > 0:
                await asyncio.sleep(wait)
            batch = _buf[:BATCH_MAX]
            del _buf[: len(batch)]
            _state["last_flush"] = time.monotonic()
            _state["flushes"] += 1
            try:
                res = await _sender["fn"](batch)
                ok, inner = _accepted(res)
                if ok:
                    _state["sent"] += len(batch)
                else:
                    _state["failed"] += len(batch)
                    logger.error("auth_shadow batch rejected rows=%d result=%.300s", len(batch), inner)
            except Exception as exc:
                _state["failed"] += len(batch)
                logger.warning("auth_shadow batch send failed rows=%d err=%s", len(batch), type(exc).__name__)
    finally:
        _state["flushing"] = False


def stats():
    return dict(_state, buffered=len(_buf), inflight=len(_tasks))
