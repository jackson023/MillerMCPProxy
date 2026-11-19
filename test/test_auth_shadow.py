"""[bug] #66018: gateway auth_shadow (batched shadow evaluation of DB-held keys). Script suite: exits non-zero on any
failure (run in cloudbuild before deploy). Standard library only."""
import asyncio
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import auth_shadow  # noqa: E402

FAILS = []


def check(name, cond):
    print(("PASS  " if cond else "FAIL  ") + name)
    if not cond:
        FAILS.append(name)


RAW = "g" * 43
SENT = []


def reset(sender=None, min_s=0.0):
    auth_shadow._buf.clear()
    auth_shadow._state.update({"flushing": False, "last_flush": -1e9, "sent": 0, "failed": 0, "dropped": 0, "flushes": 0})
    auth_shadow.FLUSH_MIN_S = min_s
    SENT.clear()
    auth_shadow.configure(sender)


async def ok_sender(rows):
    SENT.append(list(rows))
    return {"result": {"status": "ok", "written": len(rows)}}


async def rejecting_sender(rows):
    SENT.append(list(rows))
    return {"result": {"status": "error", "error": "nope"}}


async def raising_sender(rows):
    raise RuntimeError("circuit open")


async def drain():
    for _ in range(5):
        await asyncio.sleep(0)
    while auth_shadow._tasks:
        await asyncio.gather(*list(auth_shadow._tasks), return_exceptions=True)


async def main():
    check("scope: /mcp", auth_shadow.scope_for("/mcp") == "mcp")
    check("scope: /execute", auth_shadow.scope_for("/execute") == "execute")
    check("scope: /admin/restart", auth_shadow.scope_for("/admin/restart") == "admin")

    reset(ok_sender)
    auth_shadow.observe("/mcp", RAW, "current")
    auth_shadow.observe("/mcp", "wrong" * 5, "")
    auth_shadow.observe("/execute", "", "")
    await drain()
    rows = [r for b in SENT for r in b]
    check("three requests -> three rows sent", len(rows) == 3)
    check("valid key row: old True + sha256", rows[0]["old_verdict"] is True and rows[0]["key_sha256"] == hashlib.sha256(RAW.encode()).hexdigest())
    check("wrong key row: old False + a hash", rows[1]["old_verdict"] is False and len(rows[1]["key_sha256"]) == 64)
    check("no key row: old False + NULL hash", rows[2]["old_verdict"] is False and rows[2]["key_sha256"] is None)
    check("rows name the gateway and the route scope", all(r["service"] == "miller-mcp-gateway" for r in rows) and rows[2]["scope"] == "execute")
    check("raw key never leaves the gateway", all(RAW not in str(r) for r in rows))
    check("sent counter", auth_shadow._state["sent"] == 3 and auth_shadow._state["failed"] == 0)

    # batching: rows observed while a flush waits go out together, one flush in flight
    reset(ok_sender, min_s=0.05)
    auth_shadow._state["last_flush"] = time.monotonic()
    for _ in range(10):
        auth_shadow.observe("/mcp", RAW, True)
    check("one flush task in flight", len(auth_shadow._tasks) == 1)
    await drain()
    check("10 rows in one batch", [len(b) for b in SENT] == [10])

    # batch size cap
    reset(ok_sender)
    saved = auth_shadow.BATCH_MAX
    auth_shadow.BATCH_MAX = 4
    auth_shadow._state["flushing"] = True  # hold the flush while rows queue
    for _ in range(10):
        auth_shadow.observe("/mcp", RAW, True)
    auth_shadow._state["flushing"] = False
    auth_shadow._kick()
    await drain()
    auth_shadow.BATCH_MAX = saved
    check("batches capped at BATCH_MAX", [len(b) for b in SENT] == [4, 4, 2])

    # buffer cap drops instead of growing without bound
    reset(None)
    saved = auth_shadow.BUFFER_CAP
    auth_shadow.BUFFER_CAP = 3
    for _ in range(5):
        auth_shadow.observe("/mcp", RAW, True)
    auth_shadow.BUFFER_CAP = saved
    check("buffer cap drops the excess", len(auth_shadow._buf) == 3 and auth_shadow._state["dropped"] == 2)

    # rejected and failing sends are counted, never raised
    reset(rejecting_sender)
    auth_shadow.observe("/mcp", RAW, True)
    await drain()
    check("a rejected batch is counted as failed", auth_shadow._state["failed"] == 1 and auth_shadow._state["sent"] == 0)
    reset(raising_sender)
    try:
        auth_shadow.observe("/mcp", RAW, True)
        await drain()
        ok = True
    except Exception:
        ok = False
    check("a raising sender never raises into the request", ok and auth_shadow._state["failed"] == 1)

    # request-path cost
    reset(ok_sender, min_s=10.0)
    auth_shadow._state["last_flush"] = time.monotonic()
    t0 = time.perf_counter()
    for _ in range(1000):
        auth_shadow.observe("/mcp", RAW, True)
    per_ms = (time.perf_counter() - t0) * 1000 / 1000
    for t in list(auth_shadow._tasks):
        t.cancel()
    await drain()
    check(f"observe costs < 0.2 ms per request (measured {per_ms:.4f} ms)", per_ms < 0.2)


# outside an event loop: queued, not raised
reset(ok_sender)
try:
    auth_shadow.observe("/mcp", RAW, True)
    _ok = len(auth_shadow._buf) == 1
except Exception:
    _ok = False
check("observe outside an event loop queues without raising", _ok)

asyncio.run(main())
print("ALL PASS" if not FAILS else f"FAILS: {FAILS}")
sys.exit(1 if FAILS else 0)
