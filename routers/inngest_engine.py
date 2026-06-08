"""
inngest_engine.py — Miller IQ Inngest functions.
Static functions (db-operations, iq-event-dispatcher, vertex-batch-monitor),
dynamic cron engine, and inngest_functions list.
Extracted from external_router.py v4. Imported by external_router.py.
"""

from __future__ import annotations
import asyncio
import json
import logging
from typing import Any
import inngest
from routers.inngest_helpers import (  # noqa: E402
    inngest_client,
    _on_db_operation_failure,
    _on_event_dispatcher_failure,
    _on_vertex_monitor_failure,
    _on_failure,
    _dispatch,
    _write_platform_event,
    _update_scheduled_job,
    _update_background_job,
    _get_db_pool,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# STATIC INNGEST FUNCTIONS  (event-triggered only — no crons here ever again)
# ─────────────────────────────────────────────────────────────────────────────

_TRIGGER_BATCH_SIZE  = 50
_CASCADE_TRIGGER_FNS = ("fn_auto_register_entity", "fn_universal_audit_trigger")


async def _fetch_trigger_tables() -> list[str]:
    pool = _get_db_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT DISTINCT t.tgrelid::regclass::text AS tbl FROM pg_trigger t"
            " JOIN pg_proc p ON p.oid = t.tgfoid"
            " WHERE p.proname = ANY($1::text[]) AND NOT t.tgisinternal ORDER BY tbl",
            list(_CASCADE_TRIGGER_FNS),
        )
    return [r["tbl"] for r in rows]


async def _apply_trigger_batch(batch: list[str], batch_num: int, action: str) -> dict:
    pool = _get_db_pool()
    ok, errors = [], []
    async with pool.acquire() as conn:
        for tbl in batch:
            try:
                await conn.execute(f"ALTER TABLE {tbl} {action} TRIGGER USER")
                ok.append(tbl)
            except Exception as exc:
                errors.append({"table": tbl, "error": str(exc)[:120]})
    return {"batch": batch_num, "ok": len(ok), "errors": errors}


@inngest_client.create_function(
    fn_id="db-operations", name="DB Operations",
    trigger=inngest.TriggerEvent(event="platform/db.operation"),
    retries=1, on_failure=_on_db_operation_failure,
)
async def db_operations(ctx: inngest.Context) -> dict:
    data      = ctx.event.data if isinstance(ctx.event.data, dict) else {}
    operation = data.get("operation")
    run_id    = str(ctx.run_id)

    await _update_scheduled_job("db-operations", "RUNNING")
    await _write_platform_event("job.started", "db-operations",
                                 {"run_id": run_id, "operation": operation})

    if operation not in ("disable_triggers", "enable_triggers"):
        raise ValueError(f"db-operations: unknown operation '{operation}'")

    action = "ENABLE" if operation == "enable_triggers" else "DISABLE"
    op     = f"{action.lower()}_triggers"

    async def _get_tables() -> list[str]:
        return await _fetch_trigger_tables()

    tables: list[str] = await ctx.step.run("get-table-list", _get_tables)
    total       = len(tables)
    num_batches = -(-total // _TRIGGER_BATCH_SIZE)
    await _write_platform_event("job.batch_completed", "db-operations",
                                 {"run_id": run_id, "step": "get-table-list",
                                  "operation": op, "tables_found": total})

    total_ok, all_errors = 0, []
    for i in range(0, total, _TRIGGER_BATCH_SIZE):
        batch     = tables[i: i + _TRIGGER_BATCH_SIZE]
        batch_num = i // _TRIGGER_BATCH_SIZE + 1

        async def _do_batch(b: list[str] = batch, bn: int = batch_num, act: str = action) -> dict:
            return await _apply_trigger_batch(b, bn, act)

        result: dict = await ctx.step.run(f"batch-{batch_num}-of-{num_batches}", _do_batch)
        total_ok += result.get("ok", 0)
        all_errors.extend(result.get("errors", []))
        await _write_platform_event("job.batch_completed", "db-operations", {
            "run_id": run_id, "step": f"batch-{batch_num}-of-{num_batches}",
            "operation": op, "succeeded": result.get("ok", 0),
            "failed": len(result.get("errors", [])),
        })

    final_status = "SUCCESS" if not all_errors else "UNKNOWN"
    await _update_scheduled_job("db-operations", final_status)
    await _write_platform_event("job.completed", "db-operations", {
        "run_id": run_id, "operation": op,
        "total_tables": total, "succeeded": total_ok, "failed": len(all_errors),
    })
    return {"status": "ok", "run_id": run_id, "operation": op,
            "total_tables": total, "succeeded": total_ok, "failed": len(all_errors),
            "errors": all_errors}


@inngest_client.create_function(
    fn_id="iq-event-dispatcher", name="IQ Event Dispatcher",
    trigger=inngest.TriggerEvent(event="platform/tool.run"),
    retries=2, on_failure=_on_event_dispatcher_failure,
    # ── Flow control ─────────────────────────────────────────────────────────
    # Concurrency: limits actively EXECUTING steps (not queued function runs).
    # Layer 1 (account): global blast shield — max 20 tool steps executing
    #   simultaneously across the entire platform. Queues everything else.
    # Layer 2 (fn): per-tool overlap guard — max 3 concurrent instances of
    #   the same tool_name. Prevents harvest_orchestrator, sync_engine etc.
    #   from self-saturating the platform.
    # Pro plan: 100 concurrent steps available.
    # Layer 1 (account): global blast shield — max 80 tool steps executing
    #   simultaneously. Reserves 20 slots for crons + vertex monitors.
    # Layer 2 (fn): per-tool overlap guard — max 10 concurrent instances of
    #   the same tool_name. Prevents any single tool monopolizing the queue.
    concurrency=[
        inngest.Concurrency(scope="account", limit=80),
        inngest.Concurrency(scope="fn", key="event.data.tool_name", limit=10),
    ],
    # Priority: interactive always jumps the queue (+300s), agent next (+100s),
    # cron at base FIFO (0). Source injected by fire_inngest_event / fire_inngest_batch.
    priority=inngest.Priority(
        run="event.data.source == \'interactive\' ? 300 : event.data.source == \'agent\' ? 100 : 0"
    ),
)
async def iq_event_dispatcher(ctx: inngest.Context) -> dict:
    """
    HOT-RELOAD GATEWAY v3 — universal background_jobs tracking.
    Every tool execution gets a background_jobs row, regardless of how the
    event was fired (fire_inngest_event, fire_inngest_batch, cron driver,
    raw HTTP, agents). Auto-generates job_id from run_id when not provided.
    Event payload: {"tool_name": "my_tool", "args": {...}, "source": "...", "job_id": "bj-..."}
    """
    data      = ctx.event.data if isinstance(ctx.event.data, dict) else {}
    tool_name = str(data.get("tool_name", "")).strip()
    args      = data.get("args", {}) if isinstance(data.get("args"), dict) else {}
    source    = str(data.get("source", "")).strip() or "unknown"
    job_id    = str(data.get("job_id", "")).strip()
    run_id    = str(ctx.run_id)

    if not tool_name:
        raise ValueError("platform/tool.run requires tool_name in event data")

    # ── Universal job tracking ────────────────────────────────────────────────
    # If fire_inngest_event/fire_inngest_batch pre-created a background_jobs row,
    # job_id is already set. Otherwise auto-generate from run_id so every
    # execution is tracked — full observability on every single Inngest invocation.
    if not job_id:
        job_id = f"bj-{run_id[:16]}"
        pool = _get_db_pool()
        if pool:
            try:
                async with pool.acquire() as _conn:
                    await _conn.execute(
                        "INSERT INTO background_jobs "
                        "(job_id, tool_name, event_name, arguments, status, "
                        "source, is_raw_event, created_at) "
                        "VALUES ($1, $2, $3, $4::jsonb, 'pending', $5, FALSE, NOW())",
                        job_id, tool_name, "platform/tool.run",
                        json.dumps(args), source,
                    )
            except Exception as _exc:
                logger.warning(
                    "iq-event-dispatcher: auto-track insert non-fatal: %s", _exc
                )

    await _write_platform_event(
        "job.started", f"iq-event-dispatcher:{tool_name}",
        {"run_id": run_id, "tool_name": tool_name,
         "job_id": job_id, "source": source},
    )
    await _update_background_job(job_id, "running", inngest_run_id=run_id)

    async def _run_tool() -> dict:
        return await _dispatch(tool_name, args)

    result  = await ctx.step.run("run-tool", _run_tool)
    status  = result.get("status") if isinstance(result, dict) else str(result)
    err_msg = result.get("error")  if isinstance(result, dict) else None
    job_ok  = status not in ("error", "failed") if status else True

    await _update_background_job(
        job_id,
        "done" if job_ok else "error",
        result=result if isinstance(result, dict) else {"raw": str(result)},
        error=str(err_msg)[:500] if err_msg else None,
    )
    await _write_platform_event(
        "job.completed", f"iq-event-dispatcher:{tool_name}",
        {"run_id": run_id, "tool_name": tool_name, "status": status, "job_id": job_id or None},
    )
    return {"status": "ok", "run_id": run_id, "tool_name": tool_name,
            "job_id": job_id, "source": source, "result": result}


@inngest_client.create_function(
    fn_id="vertex-batch-monitor", name="Vertex Batch Monitor",
    trigger=inngest.TriggerEvent(event="platform/vertex.submitted"),
    retries=1, on_failure=_on_vertex_monitor_failure,
)
async def vertex_batch_monitor(ctx: inngest.Context) -> dict:
    """
    Durable Vertex AI batch job monitor. Polls via ctx.step.sleep().
    No blocking loops. No held connections. Runs durably up to 60 minutes.
    """
    data            = ctx.event.data if isinstance(ctx.event.data, dict) else {}
    vertex_job_name = str(data.get("vertex_job_name", "")).strip()
    vertex_db_id    = data.get("vertex_db_id")
    callback_tool   = str(data.get("callback_tool", "")).strip()
    callback_args   = data.get("callback_args") if isinstance(data.get("callback_args"), dict) else {}
    run_id          = str(ctx.run_id)

    if not vertex_job_name or vertex_db_id is None:
        raise ValueError("vertex_job_name and vertex_db_id are required in event data")
    vertex_db_id = int(vertex_db_id)

    async def _log_started(
        rid: str = run_id, jname: str = vertex_job_name,
        dbid: int = vertex_db_id, ct: str = callback_tool,
    ) -> None:
        await _write_platform_event("job.started", "vertex-batch-monitor", {
            "run_id": rid, "vertex_job_name": jname,
            "vertex_db_id": dbid, "callback_tool": ct,
        })
        await _update_scheduled_job("vertex-batch-monitor", "RUNNING")

    await ctx.step.run("log-started", _log_started)

    _MAX_POLLS, _POLL_SLEEP_S = 60, 60
    terminal_state: str | None = None

    for attempt in range(_MAX_POLLS):
        async def _poll_vertex(
            jname: str = vertex_job_name, dbid: int = vertex_db_id,
            rid: str = run_id, att: int = attempt,
        ) -> dict:
            return await _dispatch("vertex_poll_job", {
                "vertex_job_name": jname, "vertex_db_id": dbid,
                "inngest_run_id": rid, "poll_attempt": att,
            })

        poll_result = await ctx.step.run(f"poll-{attempt}", _poll_vertex)

        if not isinstance(poll_result, dict):
            await ctx.step.sleep(f"sleep-{attempt}", datetime.timedelta(seconds=_POLL_SLEEP_S))
            continue

        final_state = poll_result.get("vertex_state", "")
        is_terminal = bool(poll_result.get("terminal", False))
        succeeded   = bool(poll_result.get("succeeded", False))

        async def _log_poll(
            rid: str = run_id, att: int = attempt,
            fs: str = final_state, ti: bool = is_terminal, su: bool = succeeded,
        ) -> None:
            await _write_platform_event("job.batch_completed", "vertex-batch-monitor", {
                "run_id": rid, "attempt": att,
                "vertex_state": fs, "terminal": ti, "succeeded": su,
            })

        await ctx.step.run(f"log-poll-{attempt}", _log_poll)
        if is_terminal:
            terminal_state = final_state
            break
        await ctx.step.sleep(f"sleep-{attempt}", datetime.timedelta(seconds=_POLL_SLEEP_S))

    if terminal_state is None:
        await _update_scheduled_job("vertex-batch-monitor", "FAILURE",
                                     f"Exhausted {_MAX_POLLS} polls without terminal state")
        await _write_failure_intel("vertex-batch-monitor", run_id,
                                    f"Exhausted {_MAX_POLLS} polls x {_POLL_SLEEP_S}s")
        pool = _get_db_pool()
        if pool:
            conn = None
            try:
                conn = await asyncio.wait_for(pool.acquire(), timeout=3.0)
                await conn.execute(
                    "UPDATE platform_vertex_jobs SET status='timeout',"
                    " error_text='Inngest monitor exhausted 60 polls (60 min)',"
                    " completed_at=NOW() WHERE id=$1", vertex_db_id,
                )
            except Exception as exc:
                logger.error("vertex-batch-monitor: timeout DB update failed: %s", exc)
            finally:
                if conn is not None:
                    await pool.release(conn)
        return {"status": "error", "error": "max_polls_exhausted",
                "vertex_job_name": vertex_job_name, "run_id": run_id}

    if terminal_state != "JOB_STATE_SUCCEEDED":
        async def _log_failed(
            rid: str = run_id, ts: str = terminal_state, jname: str = vertex_job_name,
        ) -> None:
            await _write_platform_event("job.failed", "vertex-batch-monitor", {
                "run_id": rid, "vertex_state": ts, "vertex_job_name": jname,
            })
            await _update_scheduled_job("vertex-batch-monitor", "FAILURE",
                                         f"Vertex job terminal state: {ts}")
        await ctx.step.run("log-failed", _log_failed)
        return {"status": "error", "vertex_state": terminal_state,
                "vertex_job_name": vertex_job_name, "run_id": run_id}

    if callback_tool:
        async def _write_results(
            tool: str = callback_tool, ca: dict = callback_args,
            jname: str = vertex_job_name, dbid: int = vertex_db_id, rid: str = run_id,
        ) -> dict:
            return await _dispatch(tool, {
                **ca, "vertex_job_name": jname,
                "vertex_db_id": dbid, "inngest_run_id": rid,
            })
        result = await ctx.step.run("write-results", _write_results)
    else:
        result = {"status": "ok", "note": "no callback_tool specified"}

    async def _log_completed(
        rid: str = run_id, ts: str = terminal_state, ct: str = callback_tool,
        rs: str = (result.get("status") if isinstance(result, dict) else str(result)),
    ) -> None:
        await _write_platform_event("job.completed", "vertex-batch-monitor", {
            "run_id": rid, "vertex_state": ts,
            "callback_tool": ct, "result_status": rs,
        })
        await _update_scheduled_job("vertex-batch-monitor", "SUCCESS")

    await ctx.step.run("log-completed", _log_completed)
    return {"status": "ok", "run_id": run_id, "vertex_job_name": vertex_job_name,
            "vertex_state": terminal_state, "callback_result": result}
# ─────────────────────────────────────────────────────────────────────────────
# PLATFORM CRON DRIVER
# Hourly watchdog: fires at :00 every hour. Catches any cron that slipped
# through native scheduling. Dispatches to fire_inngest_batch (hot-reload).
# Primary scheduling is via individual TriggerCron functions in load_dynamic_crons().
# Add/update/enable/disable crons via: manage_cron_schedule (zero deploy).
# ─────────────────────────────────────────────────────────────────────────────

@inngest_client.create_function(
    fn_id="platform-cron-driver",
    name="Platform Cron Driver",
    trigger=inngest.TriggerCron(cron="TZ=America/Chicago 0 * * * *"),
    retries=0,
    concurrency=[inngest.Concurrency(limit=1)],
)
async def platform_cron_driver(ctx: inngest.Context) -> dict:
    """
    Hourly watchdog. Fires at :00 every hour via fire_inngest_batch cron mode.
    Catches any cron missed by native TriggerCron scheduling.
    This function body never changes — manage_cron_schedule owns all scheduling.
    """
    run_id = str(ctx.run_id)
    await _write_platform_event(
        "job.started", "platform-cron-driver", {"run_id": run_id}
    )

    async def _run() -> dict:
        return await _dispatch("fire_inngest_batch", {})

    result = await ctx.step.run("run-cron-driver", _run)

    await _write_platform_event(
        "job.completed", "platform-cron-driver",
        {"run_id": run_id, "fired": result.get("fired_count", 0)},
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# DYNAMIC CRON FUNCTIONS
# Each enabled cron in cron_schedules gets its own Inngest TriggerCron function.
# Inngest fires it at the EXACT scheduled time — no polling, no lag.
# load_dynamic_crons() called at startup (main.py lifespan) and on every
# /api/inngest/sync call (triggered by manage_cron_schedule after writes).
# ─────────────────────────────────────────────────────────────────────────────

def _build_dynamic_cron(job_name: str, cron_expr: str, tool_name: str, tool_args: dict):
    """Build one Inngest TriggerCron function for a cron_schedules row."""
    import json as _json

    @inngest_client.create_function(
        fn_id=f"cron-{job_name}",
        name=f"Cron: {job_name}",
        trigger=inngest.TriggerCron(cron=f"TZ=America/Chicago {cron_expr}"),
        concurrency=[inngest.Concurrency(limit=1)],
        retries=1,
    )
    async def _fn(ctx: inngest.Context) -> dict:
        run_id = str(ctx.run_id)
        job_id = f"bj-{run_id[:16]}"
        pool   = _get_db_pool()

        # Stamp + create background_jobs row before execution
        if pool:
            try:
                async with pool.acquire() as _c:
                    await _c.execute(
                        "UPDATE cron_schedules SET last_fired_at=NOW(), last_job_id=$1 "
                        "WHERE job_name=$2", job_id, job_name,
                    )
                    await _c.execute(
                        "INSERT INTO background_jobs "
                        "(job_id, tool_name, event_name, arguments, status, "
                        "source, is_raw_event, created_at) "
                        "VALUES ($1,$2,$3,$4::jsonb,'running',$5,FALSE,NOW())",
                        job_id, tool_name, f"cron/{job_name}",
                        _json.dumps(tool_args), "cron",
                    )
            except Exception as _exc:
                logger.warning("cron-%s: pre-flight write non-fatal: %s", job_name, _exc)

        async def _run() -> dict:
            # Inject _job_id so tools can call update_job_progress for granular progress.
            # The heartbeat fires every 30s automatically — all tools get
            # working/slow/zombie detection with zero per-tool changes required.
            _args = {**tool_args, '_job_id': job_id}

            async def _beat():
                while True:
                    await asyncio.sleep(30)
                    try:
                        async with pool.acquire() as _hc:
                            await _hc.execute(
                                'UPDATE background_jobs '
                                'SET last_heartbeat_at = NOW() WHERE job_id = $1',
                                job_id
                            )
                    except Exception:
                        pass  # Non-fatal — never block tool execution

            _hb = asyncio.create_task(_beat()) if pool else None
            try:
                return await _dispatch(tool_name, _args)
            finally:
                if _hb:
                    _hb.cancel()
                    try:
                        await _hb
                    except asyncio.CancelledError:
                        pass

        result = await ctx.step.run("run-tool", _run)

        # Write outcome to background_jobs
        if pool:
            try:
                _ok = not (isinstance(result, dict) and result.get("status") in ("error","failed"))
                async with pool.acquire() as _c:
                    await _c.execute(
                        "UPDATE background_jobs SET status=$1, result=$2::jsonb, "
                        "completed_at=NOW() WHERE job_id=$3",
                        "done" if _ok else "error",
                        _json.dumps(result if isinstance(result, dict) else {"raw": str(result)}),
                        job_id,
                    )
            except Exception as _exc:
                logger.warning("cron-%s: post-flight write non-fatal: %s", job_name, _exc)

        return result

    _fn._is_dynamic_cron = True  # flag for sync endpoint observability
    return _fn


async def load_dynamic_crons(pool=None) -> int:
    """
    Read all enabled crons from cron_schedules, build TriggerCron functions,
    append to inngest_functions (mutates in place). Called once at startup
    in main.py lifespan and on every /api/inngest/sync call.
    Returns count of dynamic functions registered.
    """
    import json as _json
    _pool = pool or _get_db_pool()
    if not _pool:
        logger.warning("load_dynamic_crons: no pool — skipping")
        return 0

    # Remove stale dynamic crons before re-registering
    inngest_functions[:] = [f for f in inngest_functions
                             if not getattr(f, "_is_dynamic_cron", False)]
    try:
        async with _pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT job_name, cron_expr, tool_name, args
                FROM   cron_schedules WHERE enabled = TRUE ORDER BY job_name
            """)
    except Exception as exc:
        logger.error("load_dynamic_crons: DB read failed: %s", exc)
        return 0

    count = 0
    for row in rows:
        raw = row["args"]
        ta  = dict(raw) if isinstance(raw, dict) else (_json.loads(raw) if raw else {})
        try:
            inngest_functions.append(
                _build_dynamic_cron(row["job_name"], row["cron_expr"], row["tool_name"], ta)
            )
            count += 1
        except Exception as exc:
            logger.error("load_dynamic_crons: failed cron-%s: %s", row["job_name"], exc)

    logger.info("load_dynamic_crons: %d dynamic cron functions registered", count)
    return count



def _build_dynamic_event_trigger(fn_id: str, event_name: str, tool_name: str):
    """Build one Inngest TriggerEvent function for an inngest_event_triggers row."""

    @inngest_client.create_function(
        fn_id=fn_id,
        name=f"Event: {fn_id}",
        trigger=inngest.TriggerEvent(event=event_name),
        retries=1,
    )
    async def _fn(ctx: inngest.Context) -> dict:
        run_id     = str(ctx.run_id)
        event_data = ctx.event.data if isinstance(ctx.event.data, dict) else {}
        return await _dispatch(tool_name, {
            "trigger_event":  ctx.event.name,
            "event_data":     event_data,
            "inngest_run_id": run_id,
        })

    _fn._is_dynamic_event_trigger = True
    return _fn


async def load_dynamic_event_triggers(pool=None) -> int:
    """
    Read all enabled event triggers from inngest_event_triggers, build
    TriggerEvent functions, append to inngest_functions (mutates in place).
    Called at startup (main.py lifespan) and on /api/inngest/sync re-registration.
    Add/update/enable/disable event triggers via: manage_inngest_event_trigger (zero deploy).
    Returns count of dynamic functions registered.
    """
    _pool = pool or _get_db_pool()
    if not _pool:
        logger.warning("load_dynamic_event_triggers: no pool — skipping")
        return 0

    inngest_functions[:] = [f for f in inngest_functions
                             if not getattr(f, "_is_dynamic_event_trigger", False)]
    try:
        async with _pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT fn_id, event_name, tool_name
                FROM   inngest_event_triggers WHERE enabled = TRUE ORDER BY fn_id
            """)
    except Exception as exc:
        logger.error("load_dynamic_event_triggers: DB read failed: %s", exc)
        return 0

    count = 0
    for row in rows:
        try:
            inngest_functions.append(
                _build_dynamic_event_trigger(row["fn_id"], row["event_name"], row["tool_name"])
            )
            count += 1
        except Exception as exc:
            logger.error("load_dynamic_event_triggers: failed %s: %s", row["fn_id"], exc)

    logger.info("load_dynamic_event_triggers: %d dynamic event trigger functions registered", count)
    return count
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# BQ DR SYNC — multi-step Inngest function.
#
# Three durable steps separated by ctx.step.sleep:
#   Step 1 — submit:  AlloyDB full table → NDJSON → GCS → BQ Load Job
#   Sleep 90 s      : Cloud Run freed. BQ does its work async.
#   Step 2 — harvest: GET BQ job status, verify integrity, update bq_dr_jobs.
#
# No asyncio.wait_for. No polling loop. No blocked event loop.
# concurrency=6: protects AlloyDB from 13 simultaneous full table reads.
# retries=2: if BQ not DONE at harvest, Inngest retries from checkpoint.
#            submit + sleep are memoised — no double-submit.
# ─────────────────────────────────────────────────────────────────────────────

@inngest_client.create_function(
    fn_id="bq-dr-sync-table",
    name="BQ DR — Sync Table",
    trigger=inngest.TriggerEvent(event="platform/bq-dr.sync-table"),
    retries=2,
    on_failure=_on_failure,
    concurrency=[inngest.Concurrency(limit=6)],
)
async def bq_dr_sync_table(ctx: inngest.Context) -> dict:
    import datetime as _dt
    import decimal  as _dec
    import uuid     as _uuid
    import google.auth
    import google.auth.transport.requests as _gtr
    import requests as _req

    _PROJECT  = "miller-iq-platform"
    _DATASET  = "millerplatformiq"
    _BUCKET   = "miller-iq-screenshots"
    _BQ_BASE  = f"https://bigquery.googleapis.com/bigquery/v2/projects/{_PROJECT}"
    _GCS_BASE = f"https://storage.googleapis.com/upload/storage/v1/b/{_BUCKET}/o"
    _SKIP_UDTS = frozenset({"vector", "tsvector"})
    _PG_TO_BQ  = {
        "integer":"INTEGER","bigint":"INTEGER","smallint":"INTEGER",
        "numeric":"FLOAT","decimal":"FLOAT","real":"FLOAT","double precision":"FLOAT",
        "text":"STRING","character varying":"STRING","character":"STRING","name":"STRING",
        "boolean":"BOOLEAN",
        "timestamp without time zone":"TIMESTAMP","timestamp with time zone":"TIMESTAMP",
        "date":"DATE","jsonb":"STRING","json":"STRING","uuid":"STRING","ARRAY":"STRING",
    }

    data       = ctx.event.data if isinstance(ctx.event.data, dict) else {}
    table_name = str(data.get("table_name", "")).strip()
    run_id     = str(ctx.run_id)
    if not table_name:
        raise ValueError("bq-dr-sync-table: table_name required in event.data")

    def _token() -> str:
        creds, _ = google.auth.default()
        creds.refresh(_gtr.Request())
        return creds.token

    def _ser(v):
        if v is None: return None
        if isinstance(v, bool): return v
        if isinstance(v, (_dt.datetime, _dt.date)): return v.isoformat()
        if isinstance(v, _dec.Decimal): return float(v)
        if isinstance(v, _uuid.UUID): return str(v)
        if isinstance(v, (dict, list)):
            return json.dumps(v, default=lambda x: x.isoformat() if hasattr(x, "isoformat") else str(x))
        return v

    # ── STEP 1: submit ─────────────────────────────────────────────────────
    async def _submit(tbl: str = table_name, rid: str = run_id) -> dict:
        pool = _get_db_pool()
        tok  = _token()
        ts   = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        async with pool.acquire() as conn:
            col_rows = await conn.fetch(
                "SELECT column_name, data_type, udt_name FROM information_schema.columns "
                "WHERE table_schema='public' AND table_name=$1 ORDER BY ordinal_position", tbl)
            schema_fields, safe_cols, skipped = [], [], []
            for c in col_rows:
                if c["udt_name"] in _SKIP_UDTS:
                    skipped.append(c["column_name"])
                else:
                    schema_fields.append({"name":c["column_name"],
                                          "type":_PG_TO_BQ.get(c["data_type"],"STRING"),
                                          "mode":"NULLABLE"})
                    safe_cols.append(c["column_name"])
            if not schema_fields:
                raise RuntimeError(f"No syncable columns in {tbl}")
            col_sql = ", ".join(f'"{c}"' for c in safe_cols)
            rows    = await conn.fetch(f'SELECT {col_sql} FROM "{tbl}"')

        rows_exported = len(rows)
        lines = [json.dumps({k: _ser(v) for k, v in dict(r).items() if k in safe_cols},
                             ensure_ascii=False) for r in rows]
        ndjson = ("\n".join(lines) + "\n").encode("utf-8") if lines else b""
        ndjson_sz = len(ndjson)

        gcs_hdrs = {"Authorization": f"Bearer {tok}", "Content-Type": "application/x-ndjson"}
        for path in (f"bq-dr/{tbl}/{ts}.ndjson", f"bq-dr/{tbl}/latest.ndjson"):
            r = _req.post(_GCS_BASE, params={"uploadType":"media","name":path},
                          headers=gcs_hdrs, data=ndjson, timeout=300)
            r.raise_for_status()
        gcs_uri = f"gs://{_BUCKET}/bq-dr/{tbl}/latest.ndjson"

        job_body = {"configuration":{"load":{
            "destinationTable":{"projectId":_PROJECT,"datasetId":_DATASET,"tableId":tbl},
            "sourceUris":[gcs_uri],"sourceFormat":"NEWLINE_DELIMITED_JSON",
            "writeDisposition":"WRITE_TRUNCATE","schema":{"fields":schema_fields},
            "ignoreUnknownValues":True,"maxBadRecords":0,"createDisposition":"CREATE_IF_NEEDED",
        }},"labels":{"source":"bq-dr","platform":"miller-iq","table":tbl[:63]}}

        r = _req.post(f"{_BQ_BASE}/jobs", headers={"Authorization":f"Bearer {tok}"},
                      json=job_body, timeout=30)
        r.raise_for_status()
        d = r.json()
        job_id   = d["jobReference"]["jobId"]
        location = d["jobReference"].get("location","us-central1")

        pool = _get_db_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO bq_dr_jobs "
                "(table_name,bq_job_id,bq_location,gcs_uri,ndjson_bytes,"
                "rows_exported,status,inngest_run_id,submitted_at) "
                "VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,NOW()) "
                "ON CONFLICT (bq_job_id) DO NOTHING",
                tbl, job_id, location, gcs_uri, ndjson_sz, rows_exported, rid)

        logger.info("bq-dr SUBMIT | table=%s rows=%d bytes=%d job=%s",
                    tbl, rows_exported, ndjson_sz, job_id)
        return {"job_id":job_id,"location":location,"gcs_uri":gcs_uri,
                "ndjson_bytes":ndjson_sz,"rows_exported":rows_exported,
                "skipped_cols":skipped,"table_name":tbl}

    submit_result = await ctx.step.run("submit-load-job", _submit)

    # ── STEP 2: sleep ──────────────────────────────────────────────────────
    # 90 s headroom for BQ. Cloud Run freed entirely during this window.
    await ctx.step.sleep("wait-for-bq", _dt.timedelta(seconds=90))

    # ── STEP 3: harvest ────────────────────────────────────────────────────
    async def _harvest(sr: dict = submit_result,
                       tbl: str = table_name,
                       rid: str = run_id) -> dict:
        pool     = _get_db_pool()
        tok      = _token()
        job_id   = sr["job_id"]
        location = sr["location"]
        rows_exp = sr["rows_exported"]

        r = _req.get(f"{_BQ_BASE}/jobs/{job_id}", params={"location":location},
                     headers={"Authorization":f"Bearer {tok}"}, timeout=15)
        r.raise_for_status()
        d    = r.json()
        state = d.get("status",{}).get("state","")
        err   = d.get("status",{}).get("errorResult")
        stats = d.get("statistics",{}).get("load",{})
        rows_loaded  = int(stats.get("outputRows",0))
        bytes_loaded = int(stats.get("outputBytes",0))

        if state != "DONE":
            logger.warning("bq-dr HARVEST: job %s state=%s — retrying", job_id, state)
            raise RuntimeError(f"BQ job {job_id} state={state} not DONE. Inngest will retry.")

        if err:
            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE bq_dr_jobs SET status='failed',error_message=$1,completed_at=NOW() "
                    "WHERE bq_job_id=$2", str(err)[:500], job_id)
            logger.error("bq-dr HARVEST FAIL | job=%s table=%s err=%s", job_id, tbl, err)
            return {"status":"failed","table_name":tbl,"job_id":job_id,
                    "error":str(err),"integrity":"UNKNOWN"}

        integrity    = "PASS" if rows_loaded == rows_exp else "FAIL"
        final_status = "ok"   if integrity  == "PASS"   else "row_mismatch"

        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE bq_dr_jobs SET status=$1,rows_loaded=$2,bytes_loaded=$3,"
                "integrity=$4,completed_at=NOW() WHERE bq_job_id=$5",
                final_status, rows_loaded, bytes_loaded, integrity, job_id)

        if integrity == "FAIL":
            logger.warning("bq-dr ROW_MISMATCH | table=%s exported=%d loaded=%d",
                           tbl, rows_exp, rows_loaded)
        else:
            logger.info("bq-dr DONE | table=%s rows=%d bytes=%d integrity=PASS",
                        tbl, rows_loaded, bytes_loaded)

        return {"status":final_status,"table_name":tbl,"job_id":job_id,"state":state,
                "rows_loaded":rows_loaded,"rows_exported":rows_exp,
                "bytes_loaded":bytes_loaded,"integrity":integrity,"inngest_run_id":rid}

    return await ctx.step.run("harvest", _harvest)

# INNGEST LIFECYCLE EVENT HANDLERS
# inngest/function.finished fires after every successful Inngest function run.
# inngest/function.failed fires after all retries are exhausted.
# Both dispatch to inngest_job_reconciler to close background_jobs rows.
# ─────────────────────────────────────────────────────────────────────────────

@inngest_client.create_function(
    fn_id="iq-job-finished-handler",
    name="IQ Job Finished Handler",
    trigger=inngest.TriggerEvent(event="inngest/function.finished"),
    retries=1,
)
async def iq_job_finished_handler(ctx: inngest.Context) -> dict:
    event_data = ctx.event.data if isinstance(ctx.event.data, dict) else {}
    return await _dispatch("inngest_job_reconciler", {
        "trigger_event":  ctx.event.name,
        "event_data":     event_data,
        "inngest_run_id": str(ctx.run_id),
    })


@inngest_client.create_function(
    fn_id="iq-job-failed-handler",
    name="IQ Job Failed Handler",
    trigger=inngest.TriggerEvent(event="inngest/function.failed"),
    retries=1,
)
async def iq_job_failed_handler(ctx: inngest.Context) -> dict:
    event_data = ctx.event.data if isinstance(ctx.event.data, dict) else {}
    return await _dispatch("inngest_job_reconciler", {
        "trigger_event":  ctx.event.name,
        "event_data":     event_data,
        "inngest_run_id": str(ctx.run_id),
    })


# ─────────────────────────────────────────────────────────────────────────────
# inngest_functions — static functions only.
# Dynamic TriggerCron functions are appended by load_dynamic_crons() at startup.
# Dynamic TriggerEvent functions are appended by load_dynamic_event_triggers() at startup.
# Never hardcode TriggerCron functions here — cron_schedules + manage_cron_schedule own scheduling.
# ─────────────────────────────────────────────────────────────────────────────

inngest_functions = [
    db_operations,
    iq_event_dispatcher,
    vertex_batch_monitor,
    platform_cron_driver,
    iq_job_finished_handler,
    iq_job_failed_handler,
    bq_dr_sync_table,
]


