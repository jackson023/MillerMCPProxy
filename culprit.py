"""culprit.py -- trace-to-line-of-code capture. Same file in every Python runtime.

[bug] #64738. Pattern: Sentry releases + in-app frames + source context, OpenTelemetry code.* attributes.

Rules this module enforces:
  * Code identity is in the frame itself: tools compile as tools/NAME.py@vN#HASH12, repo code is
    identified by (repo, commit) baked in at build time. A line number is meaningless without it.
  * Frames are captured from the live traceback object at raise time. Stack text is never parsed.
  * The culprit is the deepest IN-APP frame. Library frames are kept, never the culprit.
  * A status=error result that cannot be matched to a literal in that version's source is
    'unresolved'. Never a guess.
  * Source context is only returned when the stored code's hash equals the frame's hash.
No I/O, no network, no database: pure functions. Cost is the traceback walk on an error path.
"""
from __future__ import annotations

import ast
import hashlib
import linecache
import os
import re
import sys
import traceback
from typing import Any, Callable, Iterable

MAX_FRAMES = 12
_TOOL_FILE_RE = re.compile(r"^tools/(?P<name>[A-Za-z0-9_\-.]+)\.py@v(?P<version>\d+)#(?P<hash>[0-9a-f]{12})$")
_LEGACY_TOOL_RE = re.compile(r"^<(?:runner:)?tool:(?P<name>[^>]+)>$")
# Code compiled from a string by OUR code under an ad-hoc name: <get_token>, <brick:foo@v3>, <crj:foo>. Optional #HASH12 makes the
# source verifiable (dynamic_filename). A name with a space (<string>, <attrs generated ...>, <frozen ...>) is never ours.
_DYN_RE = re.compile(r"^<(?P<name>[A-Za-z_][A-Za-z0-9_:.@\-]{0,100}?)(?:#(?P<hash>[0-9a-f]{12}))?>$")
_DYN_NOT_APP = frozenset({"string", "stdin", "unknown", "module", "lambda", "eval", "exec", "genexpr", "listcomp", "template", "console", "input", "generated"})
_DYN_MAX = 512
_LIB_MARKERS = ("site-packages", "dist-packages", "/lib/python", "\\lib\\python", "<frozen", "node_modules")


def code_hash12(code: str | None) -> str:
    return hashlib.sha256((code or "").encode("utf-8", "replace")).hexdigest()[:12]


def tool_filename(name: str, version: Any, code: str | None) -> str:
    """The ONE place a tool's compile filename is built. Used at every compile site."""
    try:
        v = int(version)
    except (TypeError, ValueError):
        v = 0
    return f"tools/{name}.py@v{v}#{code_hash12(code)}"


def tool_ident_from_filename(filename: str | None) -> tuple[str | None, str | None]:
    """(tool name, code hash12) a compile filename carries. Reads BOTH names a tool can carry: tools/NAME.py@vN#HASH12 and
    the old <tool:NAME> (hash None: that name never said which code ran). Every reader of a compile filename goes through
    here, so a change to the name is made in one place."""
    fn = filename or ""
    m = _TOOL_FILE_RE.match(fn)
    if m:
        return m["name"], m["hash"]
    m = _LEGACY_TOOL_RE.match(fn)
    return (m["name"], None) if m else (None, None)


def tool_name_from_filename(filename: str | None) -> str | None:
    """The tool a compile filename belongs to (either name), or None for anything that is not a tool."""
    return tool_ident_from_filename(filename)[0]


def _dyn_match(filename: str | None):
    m = _DYN_RE.match(filename or "")
    return m if m and m["name"].lower() not in _DYN_NOT_APP else None


def dynamic_filename(name: str, code: str | None) -> str:
    """Compile filename for code that is compiled from a string under an ad-hoc name. The hash makes its lines verifiable."""
    return f"<{name}#{code_hash12(code)}>"


def dynamic_label_name(filename: str | None) -> str | None:
    """The name of an ad-hoc <name> frame for DB connection labels (no ':' or '@': both are separators there), else None."""
    m = _dyn_match(filename)
    return re.sub(r"[:@]", "_", m["name"]) if m else None


def build_identity(repo: str, env: dict | None = None) -> dict:
    """Repo identity baked at build time. commit is None when the build did not bake it (never guessed)."""
    e = env if env is not None else os.environ
    commit = (e.get("GIT_COMMIT_SHA") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{7,40}", commit):  # an unreplaced placeholder or junk is not an identity
        commit = None
    return {"repo": repo, "commit": commit, "revision": e.get("K_REVISION") or None}


def _classify(filename: str, repo_roots: Iterable[str], identity: dict) -> dict:
    """Return the frame identity fields for one co_filename."""
    m = _TOOL_FILE_RE.match(filename or "")
    if m:
        return {"file": f"tools/{m['name']}.py", "version": int(m["version"]), "hash": m["hash"],
                "commit": None, "repo": None, "in_app": True, "kind": "tool"}
    m = _LEGACY_TOOL_RE.match(filename or "")
    if m:  # compiled by an old build: in our code, but identity is unknown, so it can never get source
        return {"file": f"tools/{m['name']}.py", "version": None, "hash": None,
                "commit": None, "repo": None, "in_app": True, "kind": "tool_unversioned"}
    m = _dyn_match(filename)
    if m:  # our code, compiled from a string: the frame that raised is THIS one, never the caller that exec'd it
        return {"file": f"<{m['name']}>", "version": None, "hash": m["hash"],
                "commit": None, "repo": None, "in_app": True, "kind": "dynamic"}
    fn = filename or ""
    if not any(mark in fn for mark in _LIB_MARKERS) and not fn.startswith("<"):
        for root in repo_roots:
            root = root.rstrip("/") + "/"
            if fn.startswith(root):
                return {"file": fn[len(root):], "version": None, "hash": None, "commit": identity.get("commit"),
                        "repo": identity.get("repo"), "in_app": True, "kind": "repo"}
    tail = "/".join(fn.replace("\\", "/").split("/")[-2:])
    return {"file": tail, "version": None, "hash": None, "commit": None, "repo": None, "in_app": False, "kind": "library"}


def frames_from_exc(exc: BaseException | None, repo_roots: Iterable[str], identity: dict) -> list[dict]:
    """Structured frames, outermost first, from the live traceback object."""
    if exc is None or exc.__traceback__ is None:
        return []
    out: list[dict] = []
    for fs, lineno in traceback.walk_tb(exc.__traceback__):
        code = fs.f_code
        d = _classify(code.co_filename, repo_roots, identity)
        d["function"] = code.co_name
        d["line"] = int(lineno)
        d["_abs"] = code.co_filename  # internal: stripped before anything is stored
        out.append(d)
    return out


def pick_culprit(frames: list[dict]) -> dict | None:
    for f in reversed(frames):
        if f.get("in_app"):
            return f
    return None


def _cap(frames: list[dict], culprit: dict | None) -> list[dict]:
    if len(frames) <= MAX_FRAMES:
        return frames
    keep = frames[-MAX_FRAMES:]
    if culprit is not None and culprit not in keep:
        keep = [culprit] + keep[1:]
    return keep


def repo_source_context(abs_path: str | None, line: int | None, commit: str | None, radius: int = 5) -> dict:
    """Lines around a repo frame, read from the running image. The image IS the commit that was built, so these are
    the exact lines that ran. linecache is what the traceback module already uses: no extra cost on the error path."""
    if not abs_path or not line:
        return {"status": "unavailable", "why": "missing_path_or_line"}
    try:
        src = linecache.getlines(abs_path)
    except Exception:
        src = []
    if not src or line < 1 or line > len(src):
        return {"status": "unavailable", "why": "repo_file_unreadable_or_line_out_of_range"}
    lo, hi = max(1, line - radius), min(len(src), line + radius)
    return {"status": "ok", "commit": commit, "start": lo, "end": hi, "culprit_line": line,
            "lines": [{"n": i, "text": src[i - 1].rstrip("\r\n")[:240], "culprit": i == line} for i in range(lo, hi + 1)]}


def _strip_internal(frames: list[dict]) -> None:
    for f in frames:
        f.pop("_abs", None)


_SOURCES: dict[str, str] = {}  # tool name -> source last dispatched (one entry per tool; a reference, no copy)


def remember_source(name: str, code: str | None) -> None:
    """Called at every dispatch so a nested failure can show the lines of the tool that raised, not the caller's."""
    if name and code:
        _SOURCES[name] = code


_DYN_SOURCES: dict[str, str] = {}  # dynamic_filename -> the source compiled under it (bounded; filename carries the hash)


def register_dynamic(filename: str, code: str | None) -> str:
    """Remember the source compiled under a dynamic_filename so a failure inside it can show its lines. Returns filename."""
    if filename and code and _dyn_match(filename) and "#" in filename:
        if len(_DYN_SOURCES) >= _DYN_MAX and filename not in _DYN_SOURCES:
            _DYN_SOURCES.pop(next(iter(_DYN_SOURCES)), None)
        _DYN_SOURCES[filename] = code
    return filename


def culprit_from_exc(exc: BaseException | None, repo_roots: Iterable[str], identity: dict,
                     tool_code: str | None = None) -> dict:
    """The record stored with an error row. status: resolved | library_only | no_traceback.

    tool_code is the source of the tool being dispatched. It is used only when its hash equals the frame's hash, so a
    frame from some other tool or version never gets the wrong lines. The result's 'source' holds the lines."""
    frames = frames_from_exc(exc, repo_roots, identity)
    base = {"error_class": type(exc).__name__ if exc is not None else None}
    if not frames:
        return {**base, "status": "no_traceback", "frames": []}
    c = pick_culprit(frames)
    if c is None:
        _strip_internal(frames)
        return {**base, "status": "library_only", "frames": _cap(frames, None)}
    out = {**base, "status": "resolved", "file": c["file"], "function": c["function"], "line": c["line"],
           "version": c.get("version"), "hash": c.get("hash"), "commit": c.get("commit"),
           "repo": c.get("repo"), "kind": c["kind"]}
    try:
        if c["kind"] == "tool":
            # The culprit can be a tool the dispatched tool CALLED (nested), so tool_code (the dispatched tool's) is only
            # right when its hash is the frame's; otherwise use the source last dispatched under the culprit's own name.
            code = tool_code
            if code is None or code_hash12(code) != c.get("hash"):
                f = c["file"] or ""  # display path tools/NAME.py (the compile name carries @vN#HASH, the display path does not)
                nm = f[6:-3] if f.startswith("tools/") and f.endswith(".py") else ""
                code = _SOURCES.get(nm, code)
            if code is not None:
                out["source"] = source_context(code, c["line"], c.get("hash"))
        elif c["kind"] == "repo":
            out["source"] = repo_source_context(c.get("_abs"), c["line"], c.get("commit"))
        elif c["kind"] == "dynamic":
            code = _DYN_SOURCES.get(c.get("_abs") or "")
            out["source"] = (source_context(code, c["line"], c.get("hash")) if code is not None else
                             {"status": "unavailable", "why": "dynamic_source_not_registered"})
    except Exception:
        out["source"] = {"status": "unavailable", "why": "source_capture_failed"}
    _strip_internal(frames)
    out["frames"] = _cap(frames, c)
    return out


def _enclosing_function(tree: ast.AST, lineno: int) -> str | None:
    best = None
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(n, "end_lineno", n.lineno)
            if n.lineno <= lineno <= end and (best is None or n.lineno >= best[0]):
                best = (n.lineno, n.name)
    return best[1] if best else None


def _result_texts(result: Any) -> list[str]:
    if not isinstance(result, dict):
        return []
    texts = []
    for k in ("error", "message", "detail", "reason"):
        v = result.get(k)
        if isinstance(v, str) and v.strip():
            texts.append(v)
    return texts


# [bug] #64760: outcomes that are provably NOT a code failure, so they have no traceback to find. Each class names what
# the evidence is. Used only when the resolver found no single return/raise site, so an exact code site always wins.
_OUTCOME_CLASSES = (
    ("policy_block", re.compile(
        r"BLOCKED|\bwould_block\b|not read this session|No research receipt found|\bGATE_\d+:|^Tool '[^']+' is disabled"
        r"|\brecipe_mock_gate\b|different caller prefix|fix before committing|refusing to run"
        r"|is not (?:accepted|honored) for type")),
    ("input_validation", re.compile(
        r"\bis required\b|\bmust be one of\b|\brequired for type\b|^One of: \w+=|\btype=\S+ requires\b"
        r"|\bold_str matches \d+ locations?\b|\bmust be unique\b")),
    ("reference_not_found", re.compile(r"\bnot found in [a-z_]+|\bnot in the page catalog\b|^Contract not found|^Tool '[^']+' not found")),
    ("database_statement", re.compile(
        r"SQL execution failed at statement \d+/\d+|(?:column|relation|table|function) \"[^\"]+\" does not exist"
        r"|Query timed out after \d+s \(server-side statement_timeout|canceling statement due to"
        r"|UNION types \w+ and \w+ cannot be matched|operator is not unique: |operator does not exist: |\bcolumn [\w.]+ does not exist"
        r"|could not determine data type of parameter|invalid input syntax for type \w+|syntax error at or near")),
    ("precondition_not_met", re.compile(r"\bsession has no \w+ linked\b")),
    ("timeout_limit", re.compile(r"^Execution timed out after \d+s")),
    ("partial_progress", re.compile(r"\b\d+/\d+ dispatched\b")),
    # the callee answered ok / deduplicated: nothing failed, the caller just reports the dispatch as not delivered
    ("deduplicated_dispatch", re.compile(r"'delivery': 'deduplicated'")),
    # a workflow certification verdict (assertions did not pass), relayed by the caller as text
    ("verdict_not_certified", re.compile(r"\"certified\": false, \"verdict\": \"(?:failed|uncertain)\"")),
)
_BARE_STATUS_RE = re.compile(r"^status=(?:error|partial)$")
_RELAY_RE = re.compile(r"^tool reported status=(?:error|partial)")
_EMPTY_DETAIL_RE = re.compile(r":\s*$")
_EXC_TEXT_RE = re.compile(r"^[A-Z][A-Za-z]*(?:Error|Exception): ?\S")


def traceless_outcome(texts: list[str]) -> dict | None:
    """{reason, evidence} when the error text is a policy / validation / database-statement / precondition outcome."""
    for t in texts:
        for reason, rx in _OUTCOME_CLASSES:
            m = rx.search(t)
            if m:
                return {"reason": reason, "evidence": m.group(0)[:60]}
    return None


def verdict_outcome(result: Any) -> dict | None:
    """The RESULT itself is a certification verdict (certified is False, verdict failed|uncertain): data failed
    its assertions, no code failed. Structural, so it holds even when the error text is a bare status."""
    if isinstance(result, dict) and result.get("certified") is False and result.get("verdict") in ("failed", "uncertain"):
        return {"reason": "verdict_not_certified", "evidence": f"certified=False verdict={result.get('verdict')}"}
    return None


def unresolved_reason(texts: list[str]) -> str | None:
    """A stated reason for the texts that carry nothing to match, else None."""
    if all(_BARE_STATUS_RE.match(t.strip()) for t in texts):
        return "result_has_no_error_text"
    if any(_RELAY_RE.match(t.strip()) for t in texts):
        return "relay_of_callee_error"
    if any(_EMPTY_DETAIL_RE.search(t) for t in texts):
        return "empty_detail_after_colon"
    if any(_EXC_TEXT_RE.match(t.strip()) for t in texts):
        return "caught_exception_relayed"
    return None


def resolve_status_error(code: str | None, result: Any, name: str, version: Any) -> dict:
    """Resolve a status=error RESULT (no exception) to the line in that version that produced it.

    A candidate is a return/raise whose subtree holds a string literal (>= 6 chars, not a bare key)
    that appears inside the result's error text. Exactly one distinct line resolves; none or several
    is 'no_traceback' (with a stated reason) when the text is a policy / validation / database-statement / precondition
    outcome, else 'unresolved' (with a stated 'why'). Never a guess."""
    base = {"status": "unresolved", "kind": "tool_result", "file": f"tools/{name}.py", "version": version,
            "hash": code_hash12(code) if code else None, "frames": []}
    texts = _result_texts(result)
    if not code or not texts:
        return {**base, "why": "no_code" if not code else "no_error_text"}
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {**base, "why": "syntax_error"}
    skip = {"error", "status", "message", "detail", "reason", "ok", "success", "result"}
    stmts: dict[int, dict[int, str]] = {}  # one entry per return/raise STATEMENT: {literal line: literal}. A multi-line f-string
    # is ONE statement, so its fragments must not read as several candidates (that was most of 'ambiguous_N').
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Return, ast.Raise)):
            continue
        keys = {id(k) for d in ast.walk(node) if isinstance(d, ast.Dict) for k in d.keys if k is not None}
        for c in ast.walk(node):
            if id(c) in keys:  # a dict KEY names a field; it never says why the call failed
                continue
            if isinstance(c, ast.Constant) and isinstance(c.value, str):
                s = c.value.strip()
                if len(s) >= 6 and s.lower() not in skip and any(s in t for t in texts):
                    stmts.setdefault(id(node), {}).setdefault(c.lineno, s)
    if len(stmts) == 1:
        found = next(iter(stmts.values()))
        ln = min(found)
        return {**base, "status": "resolved", "line": ln, "function": _enclosing_function(tree, ln),
                "matched": found[ln][:80], "source": source_context(code, ln, base["hash"])}
    tl = traceless_outcome(texts) or verdict_outcome(result)
    if tl:  # a policy / validation / database-statement outcome: no traceback exists, and the reason is stated
        return {**base, "status": "no_traceback", **tl}
    why = unresolved_reason(texts)
    if why:
        return {**base, "why": why}
    if stmts:
        return {**base, "why": f"ambiguous_{len(stmts)}", "candidates": sorted(min(f) for f in stmts.values())[:8]}
    return {**base, "why": "no_match"}


def source_context(code: str | None, line: int | None, expected_hash: str | None, radius: int = 5) -> dict:
    """~radius lines either side, only when the stored code IS the version that ran (hash equal)."""
    if not code or not line or not expected_hash:
        return {"status": "unavailable", "why": "missing_code_line_or_hash"}
    if code_hash12(code) != expected_hash:
        return {"status": "version_mismatch", "why": "stored code hash differs from the frame's hash"}
    src = code.splitlines()
    if line < 1 or line > len(src):
        return {"status": "unavailable", "why": "line_out_of_range"}
    lo, hi = max(1, line - radius), min(len(src), line + radius)
    return {"status": "ok", "start": lo, "end": hi, "culprit_line": line,
            "lines": [{"n": i, "text": src[i - 1][:240], "culprit": i == line} for i in range(lo, hi + 1)]}


def span_attributes(culprit: dict | None) -> dict:
    """OpenTelemetry code.* attributes (+ version/commit) for the failing span."""
    if not culprit or culprit.get("status") != "resolved":
        return {"miller.culprit_status": (culprit or {}).get("status", "none")}
    a = {"code.file.path": culprit["file"], "code.function.name": culprit.get("function"),
         "code.line.number": culprit.get("line"), "miller.culprit_status": "resolved"}
    if culprit.get("version") is not None:
        a["miller.code.version"] = culprit["version"]
        a["miller.code.hash"] = culprit.get("hash")
    if culprit.get("commit"):
        a["miller.code.commit"] = culprit["commit"]
        a["miller.code.repo"] = culprit.get("repo")
    return a


def current_exc() -> BaseException | None:
    """The exception being handled right now, if any (valid inside an except block)."""
    return sys.exc_info()[1]