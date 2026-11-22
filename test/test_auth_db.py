"""Key cutover: auth_db (gateway asks db-v3 whether a platform_api_keys key may pass) and the structure of the gate in
server.py. Script suite: exits non-zero on any failure. Standard library only; the sender is a fake."""
import ast
import asyncio
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import auth_db  # noqa: E402

FAILS = []


def check(name, cond):
    print(("PASS  " if cond else "FAIL  ") + name)
    if not cond:
        FAILS.append(name)


KEY = "miq_" + "a" * 43
KEY2 = "miq_" + "b" * 43


class Clock:
    t = 1000.0


def reset(sender=None):
    auth_db._cache.clear()
    auth_db._stats.update({"asked": 0, "cached": 0, "accepted": 0, "errors": 0})
    auth_db.configure(sender)
    auth_db._now = lambda: Clock.t
    auth_db.TIMEOUT_S = 3.0


class Sender:
    def __init__(self, accept=True, status="ok", boom=False, hang=False):
        self.calls = []
        self.accept, self.status, self.boom, self.hang = accept, status, boom, hang

    async def __call__(self, h, scope):
        self.calls.append((h, scope))
        if self.boom:
            raise RuntimeError("db down")
        if self.hang:
            await asyncio.sleep(30)
        return {"result": {"status": self.status, "accept": self.accept, "mode": "enforce"}}


async def main():
    check("looks_like_key: a real-shaped key", auth_db.looks_like_key(KEY))
    check("looks_like_key: garbage, short, long, wrong prefix, odd characters, non-string all refused",
          not any(auth_db.looks_like_key(x) for x in ("garbage", "", "miq_short", KEY + "x", "xxx_" + "a" * 43, "miq_" + "a!" * 21 + "a", None, 5)))

    s = Sender()
    reset(s)
    check("accepts: db-v3 says accept -> True", await auth_db.accepts(KEY, "mcp") is True)
    check("only the sha256 and the scope leave the gateway",
          s.calls == [(hashlib.sha256(KEY.encode()).hexdigest(), "mcp")] and KEY not in str(s.calls))
    await auth_db.accepts(KEY, "mcp")
    check("second ask inside the TTL is answered from the cache", len(s.calls) == 1)
    Clock.t += auth_db.TTL_S + 1
    await auth_db.accepts(KEY, "mcp")
    check("after the TTL the gateway asks again (a revoke reaches it within the TTL)", len(s.calls) == 2)
    await auth_db.accepts(KEY, "execute")
    check("the cache is per scope", len(s.calls) == 3)

    s = Sender(accept=False)
    reset(s)
    check("accept=false (shadow mode, revoked, wrong scope) -> False", await auth_db.accepts(KEY, "mcp") is False)

    s = Sender()
    reset(s)
    for junk in ("garbage", "", None, "miq_short"):
        await auth_db.accepts(junk, "mcp")
    await auth_db.accepts(KEY, "other")
    await auth_db.accepts(KEY, "")
    check("garbage keys and unknown scopes never cost a database call", s.calls == [])

    reset(None)
    check("no sender configured -> False", await auth_db.accepts(KEY, "mcp") is False)

    s = Sender(boom=True)
    reset(s)
    check("a failing db-v3 is accept=false, never an exception", await auth_db.accepts(KEY, "mcp") is False)
    await auth_db.accepts(KEY, "mcp")
    check("an error is remembered briefly so a down database is not hammered", len(s.calls) == 1)
    Clock.t += auth_db.ERR_TTL_S + 1
    await auth_db.accepts(KEY, "mcp")
    check("after ERR_TTL the gateway tries again", len(s.calls) == 2)

    s = Sender(status="error")
    reset(s)
    check("an error status from the tool is accept=false", await auth_db.accepts(KEY, "mcp") is False)

    s = Sender(hang=True)
    reset(s)
    auth_db.TIMEOUT_S = 0.05
    check("a hung db-v3 is cut off and answers False", await auth_db.accepts(KEY, "mcp") is False)

    reset(lambda h, sc: None)
    check("a sender that returns nothing sensible is False", await auth_db.accepts(KEY, "mcp") is False)


def structure_checks():
    src = open(os.path.join(ROOT, "server.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    fns = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    pk = fns.get("_presented_key")
    check("server.py: _presented_key exists and never reads query parameters (no key in a URL)",
          pk is not None and "query_params" not in ast.get_source_segment(src, pk))
    gate = fns.get("_auth_gate")
    check("server.py: _auth_gate is async (it may ask db-v3)", isinstance(gate, ast.AsyncFunctionDef))
    awaited, calls = 0, 0
    for n in ast.walk(tree):
        if isinstance(n, ast.Await) and isinstance(n.value, ast.Call) and getattr(n.value.func, "id", "") == "_auth_gate":
            awaited += 1
        if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_auth_gate":
            calls += 1
    check("server.py: every call to _auth_gate is awaited (an un-awaited call would pass every request)",
          calls >= 3 and awaited == calls)
    check("server.py: the old key check still runs before the db-v3 question",
          src.index("matched = _key_match(presented)") < src.index("await _auth_db.accepts("))


if __name__ == "__main__":
    asyncio.run(main())
    structure_checks()
    print("RESULT OK" if not FAILS else f"FAILS: {FAILS}")
    sys.exit(1 if FAILS else 0)
