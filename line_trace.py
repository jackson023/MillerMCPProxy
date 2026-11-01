"""line_trace.py -- which lines of a tool ran on THIS call, success or failure ([bug] #64738, decision 51749).

culprit.py answers "which line failed". This answers "which lines ran" for every call, so one PTT call on any
trace shows the exact source of the version that ran with the executed lines marked, whether it succeeded or not.

How: one sys.monitoring LINE callback (Python 3.12+), installed once. Code that is not tool code (no
`tools/NAME.py@vN#HASH12` or `<name#HASH12>` compile name) returns DISABLE, so after its first hit it costs nothing.
Tool code is never disabled. The per-call recorder lives in a ContextVar, so concurrent and nested dispatches each
get their own line set (a nested _dispatch begins its own recorder and restores its caller's on exit).

Cost bounds (measured, see the bug): ~80 ns per executed tool line; a call that executes more than BUDGET line
events stops recording (truncated=True) and its locations are re-armed for the next call. Nothing here ever raises
into the caller: on any problem begin() returns None and the call runs untraced.

Kill switch: env MILLER_LINE_TRACE=0 (or off/false) leaves the callback uninstalled.
"""
from __future__ import annotations

import contextvars
import os
import re
import sys

__all__ = ["begin", "end", "enable", "add_repo_root", "span_attributes", "status", "ranges", "BUDGET"]
VERSION = "1.1.0"
BUDGET = 50_000          # line events recorded per call before it is cut
MAX_ATTR_CHARS = 3000    # size of the stored line record per span
_ID = 1                  # sys.monitoring.COVERAGE_ID: nothing else on the platform uses it
_M = getattr(sys, "monitoring", None)
_OFF = os.environ.get("MILLER_LINE_TRACE", "1").strip().lower() in ("0", "off", "false", "no")

# Compile names that carry a code identity (culprit.tool_filename / dynamic_filename / dyn_compile): only these are tool code.
_TOOL_RE = re.compile(r"^(?:tools/[^/<>]+\.py@v\d+#[0-9a-f]{12}|<[^<>]*#[0-9a-f]{12}>)$")

_cur: contextvars.ContextVar = contextvars.ContextVar("miller_line_rec", default=None)
_kind: dict = {}         # co_filename -> is recordable code: True (tool code), True (repo file, see _repo_rel) or False (bounded)
_repo_roots: list = []   # directories whose .py files are this service's OWN code (add_repo_root); tool code needs none
_repo_rel: dict = {}     # co_filename -> path relative to its root, for repo files
_state = {"on": False, "epoch": 0, "dirty": False, "why": None, "cuts": 0}


class _Rec:
    __slots__ = ("lines", "last", "n", "cut", "epoch", "token", "done")

    def __init__(self):
        self.lines: dict = {}
        self.last: dict = {}
        self.n = 0
        self.cut = False
        self.epoch = _state["epoch"]
        self.token = None
        self.done = False


def add_repo_root(root: str) -> None:
    """Also record the service's OWN code (every .py under root, never site-packages), keyed by its path under root.
    For a service with no tool code to run (the gateway): what ran for a request is its own server code at its commit."""
    try:
        r = os.path.abspath(root).rstrip(os.sep) + os.sep
        if r not in _repo_roots:
            _repo_roots.append(r)
            _kind.clear()
    except Exception:
        pass


def _classify(fn: str) -> bool:
    if _TOOL_RE.match(fn):
        return True
    if _repo_roots and fn.endswith(".py") and "site-packages" not in fn and "dist-packages" not in fn \
            and os.path.basename(fn) != "line_trace.py":     # the recorder never records itself
        for r in _repo_roots:
            if fn.startswith(r):
                _repo_rel[fn] = fn[len(r):]
                return True
    return False


def _on_line(code, line):
    try:
        fn = code.co_filename
        ok = _kind.get(fn)
        if ok is None:
            if len(_kind) > 20000:
                _kind.clear()
            ok = _kind[fn] = _classify(fn)
        if not ok:
            return _M.DISABLE            # not tool code: never called again for this line
        rec = _cur.get()
        if rec is None or rec.done:
            return None
        rec.n += 1
        if rec.n > BUDGET:
            rec.cut = True               # stop paying for this call: disable this line until the next begin() re-arms
            _state["dirty"] = True
            _state["epoch"] += 1
            _state["cuts"] += 1
            return _M.DISABLE
        s = rec.lines.get(fn)
        if s is None:
            s = rec.lines[fn] = set()
        s.add(line)
        rec.last[fn] = line
    except Exception:
        return None
    return None


def enable() -> bool:
    """Install the callback once. False (and status()['why']) when off, unsupported or the monitoring id is taken."""
    if _state["on"]:
        return True
    if _OFF:
        _state["why"] = "disabled_by_env"
        return False
    if _M is None:
        _state["why"] = "python_lt_3_12"
        return False
    try:
        _M.use_tool_id(_ID, "miller_line_trace")
        _M.register_callback(_ID, _M.events.LINE, _on_line)
        _M.set_events(_ID, _M.events.LINE)
        _state["on"], _state["why"] = True, None
        return True
    except Exception as exc:
        _state["why"] = "install_failed: " + str(exc)[:80]
        return False


def begin():
    """Start recording for the call about to run. Returns the recorder, or None (call runs untraced)."""
    try:
        if not _state["on"] and not enable():
            return None
        if _state["dirty"]:              # a previous call was cut: re-arm the disabled tool lines before this one starts
            _state["dirty"] = False
            _M.restart_events()
            _state["epoch"] += 1
        rec = _Rec()
        rec.token = _cur.set(rec)
        return rec
    except Exception:
        return None


def end(rec):
    """Stop recording and return the summary dict (or None). Never raises."""
    if rec is None:
        return None
    try:
        rec.done = True
        try:
            _cur.reset(rec.token)
        except Exception:
            _cur.set(None)
        return {"lines": rec.lines, "last": rec.last, "n": rec.n, "cut": rec.cut,
                "partial": rec.cut or rec.epoch != _state["epoch"]}
    except Exception:
        return None


def ranges(nums) -> str:
    """[3,4,5,9,11,12] -> '3-5,9,11-12'"""
    out, start, prev = [], None, None
    for n in sorted(nums):
        if start is None:
            start = prev = n
        elif n == prev + 1:
            prev = n
        else:
            out.append(str(start) if start == prev else f"{start}-{prev}")
            start = prev = n
    if start is not None:
        out.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(out)


def span_attributes(summary, tool_name: str | None = None) -> dict:
    """The dispatch-span attribute for one call: {'lines_ran': {'f': {compile name: 'ranges'}, 'last': N, 'n': events,
    'cut': bool, 'partial': bool}}. 'last' is the last line the tool's OWN file reached: the return line on success,
    the line that raised on failure. {} when nothing was recorded. Never raises."""
    try:
        if not summary or not summary.get("lines"):
            return {}
        files = {_repo_rel.get(fn, fn): ranges(s) for fn, s in summary["lines"].items()}
        total = sum(len(v) for v in files.values())
        rec = {"f": files, "n": summary["n"]}
        own = next((fn for fn in files if tool_name and fn.startswith(f"tools/{tool_name}.py@")), None)
        if own:
            rec["last"] = summary["last"].get(own)   # a request's repo files have no single last line
        if summary.get("cut"):
            rec["cut"] = True
        if summary.get("partial"):
            rec["partial"] = True
        if total > MAX_ATTR_CHARS:       # keep the record to the size cap, cut only at a range boundary, flag it
            keep, used = {}, 0
            for k in ([own] if own else []) + [k for k in files if k != own]:
                v = files[k]
                room = MAX_ATTR_CHARS - used
                if room <= 0:
                    break
                if len(v) > room:
                    v = v[:room].rsplit(",", 1)[0] if "," in v[:room] else ""
                if v:
                    keep[k] = v
                    used += len(v)
                if own:
                    break                # a tool call keeps its own file only
            rec["f"] = keep
            rec["clipped"] = True
        return {"lines_ran": rec}
    except Exception:
        return {}


def status() -> dict:
    return {"version": VERSION, "on": _state["on"], "why": _state["why"], "budget": BUDGET, "cuts": _state["cuts"]}