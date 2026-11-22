"""Every local module the app imports must be COPYed into the image (a miss = boot crash on Cloud Run).
Script-style: prints RESULT OK / RESULT FAIL. Skips when the tree has no server.py or Dockerfile."""
import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def local_imports(path, seen):
    name = os.path.basename(path)
    if name in seen:
        return
    seen.add(name)
    tree = ast.parse(open(path, encoding="utf-8").read())
    for node in ast.walk(tree):
        mods = []
        if isinstance(node, ast.Import):
            mods = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods = [node.module.split(".")[0]]
        for m in mods:
            p = os.path.join(ROOT, m + ".py")
            if os.path.isfile(p):
                local_imports(p, seen)


def check():
    server = os.path.join(ROOT, "server.py")
    dockerfile = os.path.join(ROOT, "Dockerfile")
    if not (os.path.isfile(server) and os.path.isfile(dockerfile)):
        return None, []
    seen = set()
    local_imports(server, seen)
    copied = set()
    for line in open(dockerfile, encoding="utf-8").read().splitlines():
        if line.startswith("COPY "):
            copied.update(t for t in line.split()[1:-1] if t.endswith(".py"))
    return sorted(seen), [
        "%s is imported by server.py but not COPYed in Dockerfile" % f for f in sorted(seen) if f not in copied
    ]


def main():
    seen, fails = check()
    if seen is None:
        print("SKIP: server.py or Dockerfile not in this tree")
        return 0
    print("modules:", seen)
    print("RESULT OK" if not fails else "RESULT FAIL: " + "; ".join(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
