"""[bug] #64830: meta_tool inner-argument parsing. Script suite: exits non-zero on any failure (run in cloudbuild
before deploy). Standard library only."""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from arg_parse import parse_inner_args  # noqa: E402

FAILS = []


def check(name, cond):
    print(("PASS  " if cond else "FAIL  ") + name)
    if not cond:
        FAILS.append(name)


good = {"session_key": "s", "title": "t; it's", "symptom": "x" * 900, "root_cause": "r", "prevention": "p"}
s = json.dumps(good)

a, note, err = parse_inner_args(s)
check("clean object parses with no repair note", a == good and note is None and err is None)

a, note, err = parse_inner_args(s + "}")
check("one stray closing brace (the #64830 shape) is dropped losslessly", a == good and err is None)
check("the repair is reported", note == {"parsed_as": "json", "dropped_trailing": "}"})

a, note, err = parse_inner_args(s + "]}\n")
check("a run of closers and whitespace is dropped", a == good and note["dropped_trailing"] == "]}")

a, note, err = parse_inner_args(s + ', "b": 2}')
check("real trailing data is refused, never guessed", a is None and "Extra data" in err and '"b"' in err)

BS = chr(92)  # one backslash, spelled out so the cases are unambiguous
# wire text {"a": "c:\\\'x"} -> escaped backslash, then a stray-escaped quote: value is  c:\'x
a, note, err = parse_inner_args('{"a": "c:' + BS + BS + BS + "'" + 'x"}')
check("an escaped backslash before a stray-escaped quote stays a backslash", a == {"a": "c:" + BS + "'x"})

# wire text {"a": "it\'s"} -> invalid JSON escape \' (Python style): value is  it's
a, note, err = parse_inner_args('{"a": "it' + BS + "'" + 's"}')
check("Python-style escaped quote is repaired (S1171)", a == {"a": "it's"} and note["parsed_as"] == "json_sanitized_escapes")

a, note, err = parse_inner_args('{"a": "line' + BS + 'nnext ' + BS + 'u00e9 ' + BS + '"q' + BS + '""}')
check("valid escapes are untouched", a == {"a": 'line' + chr(10) + 'next ' + chr(233) + ' "q"'} and note is None)

a, note, err = parse_inner_args("[1, 2]")
check("a non-object is refused", a is None and "not an object" in err)

a, note, err = parse_inner_args('{"a": 1')
check("a truncated object is refused", a is None and err)

a, note, err = parse_inner_args('  {"a": {"b": [1]}}  ')
check("surrounding whitespace is fine and is not a repair", a == {"a": {"b": [1]}} and note is None)

print("RESULT OK" if not FAILS else "RESULT FAIL: %s" % FAILS)
sys.exit(1 if FAILS else 0)