#!/usr/bin/env python3
"""
scripts/build_telemetry.py — Miller IQ Platform build telemetry helper.

Called by cloudbuild.yaml steps via environment variables.
Posts structured spans to platform_traces via record_build_span.

Usage (env vars drive behaviour):
  STEP=build_started
  STEP=docker_build_complete  CACHED_LAYERS=5 REBUILT_LAYERS=2
  STEP=image_push_complete    IMAGE_DIGEST=sha256:...
  STEP=smoke_test             (reads /workspace/smoke_stderr.txt, /workspace/pip_freeze.txt)
  STEP=deploy_complete        REVISION=... ROLLBACK=... CR_STATUS=True|False

Required env vars for all steps:
  BUILD_ID, COMMIT_SHA, SHORT_SHA, GATEWAY_URL, GATEWAY_KEY
  STEP, STATUS (ok|error)
"""
import json
import os
import re
import sys
import urllib.request
import urllib.error

GATEWAY   = os.environ.get('GATEWAY_URL', '')
API_KEY   = os.environ.get('GATEWAY_KEY', '')
BUILD_ID  = os.environ.get('BUILD_ID', '')
COMMIT_SHA= os.environ.get('COMMIT_SHA', '')
SHORT_SHA = os.environ.get('SHORT_SHA', '')
STEP      = os.environ.get('STEP', '')
STATUS    = os.environ.get('STATUS', 'ok')
REPO      = os.environ.get('REPO', 'MillerMCPDB')


def post_span(attrs: dict) -> bool:
    payload = {
        'tool_name': 'record_build_span',
        'arguments': {
            'build_id':         BUILD_ID,
            'commit_sha':       COMMIT_SHA,
            'commit_sha_short': SHORT_SHA,
            'repo':             REPO,
            'step':             STEP,
            'status':           STATUS,
            'duration_ms':      0,
            'attributes':       attrs
        }
    }
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        GATEWAY,
        data=body,
        headers={
            'Content-Type': 'application/json',
            'X-API-Key': API_KEY
        },
        method='POST'
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            result = json.loads(resp.read())
            print(f"[telemetry] span written: trace_id={result.get('trace_id','?')} step={STEP}")
            return True
    except Exception as e:
        print(f"[telemetry] WARNING: span post failed (non-fatal): {e}", file=sys.stderr)
        return False


def step_build_started():
    changed_raw = os.environ.get('CHANGED_FILES', '')
    infra_raw   = os.environ.get('INFRA_FILES', '')
    commit_msg  = os.environ.get('COMMIT_MSG', '')[:200]
    all_files   = [f.strip() for f in changed_raw.split('\n') if f.strip()][:30]
    infra_files = [f.strip() for f in infra_raw.split('\n') if f.strip()]
    return {
        'infra_files_changed': infra_files,
        'changed_files':       all_files,
        'commit_message':      commit_msg
    }


def step_docker_build_complete():
    cached   = int(os.environ.get('CACHED_LAYERS', '0'))
    rebuilt  = int(os.environ.get('REBUILT_LAYERS', '0'))
    total    = cached + rebuilt
    pct      = round(cached / total * 100, 1) if total > 0 else 0.0
    return {
        'cached_layers':   cached,
        'rebuilt_layers':  rebuilt,
        'total_layers':    total,
        'layer_cache_pct': pct
    }


def step_image_push_complete():
    return {
        'image':        os.environ.get('IMAGE', ''),
        'image_digest': os.environ.get('IMAGE_DIGEST', '')
    }


def parse_pip_freeze(path='/workspace/pip_freeze.txt'):
    pip = {}
    try:
        for line in open(path):
            if '==' in line:
                pkg, ver = line.strip().split('==', 1)
                pip[pkg.lower()] = ver
    except Exception:
        pass
    return pip


def parse_traceback(stderr: str):
    error_type = ''
    error_msg  = ''
    err_file   = ''
    err_line   = 0
    snippet    = []

    for line in reversed(stderr.splitlines()):
        m = re.match(r'^([A-Za-z][A-Za-z0-9_.]*(?:Error|Exception|Warning)): (.+)$', line.strip())
        if m:
            error_type = m.group(1)
            error_msg  = m.group(2)[:300]
            break

    file_matches = list(re.finditer(r'File "([^"]+)", line (\d+)', stderr))
    if file_matches:
        last = file_matches[-1]
        err_file = last.group(1)
        err_line = int(last.group(2))
        try:
            with open(err_file) as f:
                src = f.readlines()
            start = max(0, err_line - 3)
            end   = min(len(src), err_line + 2)
            snippet = [
                '{}{}  {}'.format(i+1, '->' if i+1==err_line else '  ', src[i].rstrip())
                for i in range(start, end)
            ]
        except Exception:
            pass

    return error_type, error_msg, err_file, err_line, snippet


def step_smoke_test():
    stderr = ''
    try:
        stderr = open('/workspace/smoke_stderr.txt').read()
    except Exception:
        pass
    exit_code = int(os.environ.get('EXIT_CODE', '0'))
    pip_now   = parse_pip_freeze('/workspace/pip_freeze.txt')

    attrs = {
        'exit_code':          exit_code,
        'pip_freeze_current': pip_now,
        'full_stderr':        stderr[:2000]
    }

    if STATUS == 'error':
        et, em, ef, el, sn = parse_traceback(stderr)
        attrs.update({
            'error_type':   et,
            'error_msg':    em,
            'error_file':   ef,
            'error_line':   el,
            'code_snippet': sn
        })

    return attrs


def step_deploy_complete():
    return {
        'revision_name':     os.environ.get('REVISION', ''),
        'rollback_revision': os.environ.get('ROLLBACK', ''),
        'cloud_run_status':  os.environ.get('CR_STATUS', ''),
        'image':             os.environ.get('IMAGE', '')
    }


STEP_HANDLERS = {
    'build_started':         step_build_started,
    'docker_build_complete': step_docker_build_complete,
    'image_push_complete':   step_image_push_complete,
    'smoke_test':            step_smoke_test,
    'deploy_complete':       step_deploy_complete,
}

if __name__ == '__main__':
    if not STEP:
        print('ERROR: STEP env var required', file=sys.stderr)
        sys.exit(1)
    if not GATEWAY or not API_KEY:
        print('ERROR: GATEWAY_URL and GATEWAY_KEY required', file=sys.stderr)
        sys.exit(1)

    handler = STEP_HANDLERS.get(STEP)
    attrs   = handler() if handler else {}
    post_span(attrs)
    sys.exit(0)