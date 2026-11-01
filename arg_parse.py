"""The ONE parser for meta_tool's string-serialized inner arguments ([bug] #64830).

Both proxy paths (MCP JSON-RPC _handle_tools_call and REST _unwrap_meta_tool_rest) call parse_inner_args, so a fix
lands once. Standard library only, so test/test_arg_parse.py runs in the build without the service's dependencies.

Root cause of #64830: a caller (the MCP client serializing a model's tool call) sometimes sends a complete JSON object
followed by one stray closing bracket. json.loads fails with "Extra data: line 1 column N (char N-1)" at the final
character and the whole call was refused. The object is already fully decoded at that point and a run of closing
brackets carries no data, so dropping it is lossless; it is reported, never silent. Any other trailing text is a real
error and is refused with the tail shown.
"""
import json
import re

_CLOSERS = set("}] \t\r\n")
_ESCAPE_PAIR = re.compile(r"\\(.)", re.S)
_VALID_ESCAPES = set('"\\/bfnrtu')


def sanitize_json_escapes(s):
    """Strip the backslash of an escape JSON does not allow (S1171): Python-style \\' becomes '.

    Escapes are consumed left to right as pairs, so an escaped backslash (\\\\) is kept whole even when a quote
    follows it. (The old lookahead regex listed ' as valid -- so \\' was never fixed -- and could split \\\\.)"""
    return _ESCAPE_PAIR.sub(lambda m: m.group(0) if m.group(1) in _VALID_ESCAPES else m.group(1), s)


def _decode_object(text):
    text = text.strip()
    obj, end = json.JSONDecoder().raw_decode(text)
    tail = text[end:]
    if tail and not set(tail) <= _CLOSERS:
        raise ValueError("Extra data after the arguments object at char %d: %r" % (end, tail[:60]))
    if not isinstance(obj, dict):
        raise ValueError("arguments decoded to %s, not an object" % type(obj).__name__)
    return obj, tail.strip()


def parse_inner_args(raw):
    """Returns (args, repair_note, error). Exactly one of args / error is set.

    repair_note is None for a clean parse, else {"parsed_as": ..., "dropped_trailing": ...} so the caller can see
    its arguments needed repair."""
    errors = []
    for how, candidate in (("json", raw), ("json_sanitized_escapes", sanitize_json_escapes(raw))):
        try:
            obj, dropped = _decode_object(candidate)
        except Exception as exc:
            errors.append("%s: %s" % (how, exc))
            continue
        note = None if (how == "json" and not dropped) else {"parsed_as": how, "dropped_trailing": dropped or None}
        return obj, note, None
    return None, None, "; ".join(errors)