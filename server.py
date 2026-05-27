"""
Miller IQ Platform — Horizon MCP Gateway
==========================================
Enterprise-grade MCP transport layer with resilience.

This is the ONLY entry point for Claude.ai into the Miller IQ Platform.
Horizon handles MCP protocol, OAuth, and session management.

Resilience layers (using FastMCP native middleware + custom):
    1. ErrorHandlingMiddleware  — catches all exceptions, structured error responses
    2. RateLimitingMiddleware   — protects against request floods
    3. TimingMiddleware         — performance monitoring on every call
    4. LoggingMiddleware        — structured logging for all MCP traffic
    5. CircuitBreakerMiddleware — custom: stops hammering broken Cloud Run backend
    6. Timeout enforcement      — 30s max via httpx, clean errors on breach
    7. Retry on 503             — one retry with backoff for cold starts

Design principle: Horizon is infrastructure. Zero business logic.
"""

import asyncio
import json
import time
from typing import Any, Dict, Optional

import httpx
from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.middleware.error_handling import ErrorHandlingMiddleware
from fastmcp.server.middleware.rate_limiting import RateLimitingMiddleware
from fastmcp.server.middleware.timing import TimingMiddleware
from fastmcp.server.middleware.logging import LoggingMiddleware


# ============================================================================
# CONFIGURATION
# ============================================================================

CLOUD_RUN_URL = "https://miller-mcp-db-146372550543.us-central1.run.app"
API_KEY = "miller-techstack-2026"

# Timeouts
EXECUTE_TIMEOUT = 30.0        # Max seconds to wait for /execute
HEALTH_CHECK_TIMEOUT = 5.0    # Max seconds for health probe
RETRY_DELAY = 1.0             # Seconds before retry on 503

# Circuit breaker
CB_FAILURE_THRESHOLD = 3      # Failures before circuit opens
CB_RECOVERY_TIMEOUT = 30.0    # Seconds before trying again
CB_HEALTH_INTERVAL = 15.0     # Seconds between background health checks


# ============================================================================
# CIRCUIT BREAKER STATE
# ============================================================================

class CircuitState:
    """
    Three states: CLOSED (normal), OPEN (blocking), HALF_OPEN (probing).
    Shared across all requests via module-level singleton.
    """

    def __init__(self, failure_threshold: int, recovery_timeout: float):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = "CLOSED"
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.last_success_time = time.monotonic()

    def can_execute(self) -> bool:
        if self.state == "CLOSED":
            return True
        if self.state == "OPEN":
            if time.monotonic() - self.last_failure_time >= self.recovery_timeout:
                self.state = "HALF_OPEN"
                return True
            return False
        if self.state == "HALF_OPEN":
            return True
        return False

    def record_success(self) -> None:
        self.failure_count = 0
        self.state = "CLOSED"
        self.last_success_time = time.monotonic()

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = time.monotonic()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"

    def status(self) -> dict:
        return {
            "state": self.state,
            "failure_count": self.failure_count,
            "failure_threshold": self.failure_threshold,
            "seconds_since_last_success": round(
                time.monotonic() - self.last_success_time, 1
            ),
            "seconds_since_last_failure": (
                round(time.monotonic() - self.last_failure_time, 1)
                if self.last_failure_time > 0 else None
            ),
        }


circuit = CircuitState(
    failure_threshold=CB_FAILURE_THRESHOLD,
    recovery_timeout=CB_RECOVERY_TIMEOUT,
)


# ============================================================================
# CUSTOM FASTMCP MIDDLEWARE: Circuit Breaker
# ============================================================================

class CircuitBreakerMiddleware(Middleware):
    """
    FastMCP-native circuit breaker middleware.

    Intercepts tool calls at the MCP protocol level (on_call_tool hook).
    If the circuit is OPEN, rejects immediately with a structured error.
    Records success/failure after the tool executes.

    Uses the FastMCP middleware API (v2.9+) — works across all transports,
    not just HTTP.
    """

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        tool_name = context.message.name

        # Local diagnostic tools bypass the circuit — they don't hit Cloud Run
        if tool_name in ("ping", "horizon_status"):
            return await call_next(context)

        if not circuit.can_execute():
            from mcp import McpError
            from mcp.types import ErrorData
            raise McpError(
                ErrorData(
                    code=-32000,
                    message=(
                        f"Circuit breaker OPEN — Cloud Run backend is down. "
                        f"Will retry automatically in {int(CB_RECOVERY_TIMEOUT)}s. "
                        f"State: {json.dumps(circuit.status())}"
                    ),
                )
            )

        try:
            result = await call_next(context)
            circuit.record_success()
            return result
        except Exception as exc:
            error_str = str(exc)
            # Only trip the circuit on infrastructure failures, not tool-level errors
            if any(s in error_str for s in [
                "Cloud Run returned 5",
                "did not respond within",
                "Cannot reach Cloud Run",
                "connection_failed",
            ]):
                circuit.record_failure()
            raise


# ============================================================================
# BACKEND HEALTH MONITOR
# ============================================================================

class BackendHealth:
    """Tracks Cloud Run health via periodic background checks."""

    def __init__(self):
        self.healthy = True
        self.last_check_time = 0.0
        self.last_check_result: Optional[dict] = None
        self.tool_count = 0
        self.consecutive_failures = 0

    async def check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=HEALTH_CHECK_TIMEOUT) as client:
                resp = await client.get(
                    f"{CLOUD_RUN_URL}/health",
                    headers={"X-API-Key": API_KEY},
                )
            if resp.status_code == 200:
                data = resp.json()
                self.healthy = data.get("status") == "ok"
                self.tool_count = data.get("tool_count", 0)
                self.last_check_result = data
                self.consecutive_failures = 0
            else:
                self.healthy = False
                self.consecutive_failures += 1
                self.last_check_result = {"http_code": resp.status_code}
        except Exception as exc:
            self.healthy = False
            self.consecutive_failures += 1
            self.last_check_result = {"error": str(exc)[:200]}

        self.last_check_time = time.monotonic()
        return self.healthy

    def status(self) -> dict:
        return {
            "healthy": self.healthy,
            "tool_count": self.tool_count,
            "consecutive_failures": self.consecutive_failures,
            "seconds_since_check": (
                round(time.monotonic() - self.last_check_time, 1)
                if self.last_check_time > 0 else None
            ),
            "last_result": self.last_check_result,
        }


backend = BackendHealth()

_health_task: Optional[asyncio.Task] = None


async def _health_loop():
    """Periodically check Cloud Run health and update circuit breaker."""
    while True:
        try:
            healthy = await backend.check()
            if healthy and circuit.state in ("OPEN", "HALF_OPEN"):
                circuit.record_success()
        except Exception:
            pass
        await asyncio.sleep(CB_HEALTH_INTERVAL)


def _ensure_health_loop():
    """Start the background health loop if not running."""
    global _health_task
    if _health_task is None or _health_task.done():
        _health_task = asyncio.create_task(_health_loop())


# ============================================================================
# CORE: Forward to Cloud Run /execute
# ============================================================================

async def _forward_to_cloud_run(tool_name: str, arguments: dict) -> Any:
    """
    POST to Cloud Run /execute with resilience.
    One retry on 503 (cold start). 30s timeout.
    """
    payload = {"tool_name": tool_name, "arguments": arguments}
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=EXECUTE_TIMEOUT) as client:
        resp = await client.post(
            f"{CLOUD_RUN_URL}/execute", json=payload, headers=headers,
        )

    if resp.status_code == 200:
        data = resp.json()
        if data.get("status") == "ok":
            return data.get("result", data)
        return data

    # Retry once on 503 (cold start / scaling)
    if resp.status_code == 503:
        await asyncio.sleep(RETRY_DELAY)
        async with httpx.AsyncClient(timeout=EXECUTE_TIMEOUT) as client:
            resp2 = await client.post(
                f"{CLOUD_RUN_URL}/execute", json=payload, headers=headers,
            )
        if resp2.status_code == 200:
            data = resp2.json()
            if data.get("status") == "ok":
                return data.get("result", data)
            return data
        raise RuntimeError(
            f"Cloud Run returned {resp2.status_code} after retry"
        )

    # Non-transient failure
    try:
        body = resp.json()
    except Exception:
        body = resp.text[:500]

    return {
        "status": "error",
        "error": f"Cloud Run returned {resp.status_code}",
        "http_code": resp.status_code,
        "body": json.dumps(body) if isinstance(body, dict) else str(body),
    }


# ============================================================================
# MCP SERVER — with FastMCP native middleware stack
# ============================================================================

mcp = FastMCP("MillerMCPDB")

# Middleware stack (execution order: first added = outermost)
# 1. Error handling — outermost, catches everything
mcp.add_middleware(ErrorHandlingMiddleware())
# 2. Rate limiting — reject floods before they hit the backend
mcp.add_middleware(RateLimitingMiddleware(max_requests_per_second=10))
# 3. Timing — measure every operation
mcp.add_middleware(TimingMiddleware())
# 4. Logging — structured logs for all MCP traffic
mcp.add_middleware(LoggingMiddleware())
# 5. Circuit breaker — custom, protects Cloud Run from cascading failures
mcp.add_middleware(CircuitBreakerMiddleware())


# ============================================================================
# TOOLS
# ============================================================================

@mcp.tool()
async def meta_tool(tool_name: str, arguments: Any = None) -> Any:
    """
    Execute any tool stored in the Postgres tool registry by name.

    This is the single entry point for all custom tools. When a user asks
    you to use a specific tool (e.g. "use the save_memory tool" or "send a
    prompt to the Gemini agent"), call this with the tool's name and any
    required arguments.

    Args:
        tool_name:  Name of the tool to run, exactly as stored in Postgres.
        arguments:  Key/value pairs the tool needs (omit or pass null if none required).

    Returns the tool's result directly.
    """
    _ensure_health_loop()
    args = arguments if isinstance(arguments, dict) else (arguments or {})
    return await _forward_to_cloud_run(tool_name, args)


@mcp.tool()
def ping() -> str:
    """Returns pong to verify Horizon MCP connectivity. Does not touch Cloud Run."""
    return "pong — Miller IQ Platform is alive"


@mcp.tool()
def horizon_status() -> dict:
    """
    Returns the current health of the Horizon gateway.
    Shows circuit breaker state, backend health, and config.
    Does not touch Cloud Run — pure Horizon diagnostics.
    """
    return {
        "gateway": "Horizon MCP Gateway v2 — Enterprise",
        "circuit": circuit.status(),
        "backend": backend.status(),
        "middleware": [
            "ErrorHandlingMiddleware (FastMCP native)",
            "RateLimitingMiddleware (FastMCP native, 10 req/s)",
            "TimingMiddleware (FastMCP native)",
            "LoggingMiddleware (FastMCP native)",
            "CircuitBreakerMiddleware (custom, threshold=3, recovery=30s)",
        ],
        "config": {
            "cloud_run_url": CLOUD_RUN_URL,
            "execute_timeout_seconds": EXECUTE_TIMEOUT,
            "health_check_interval_seconds": CB_HEALTH_INTERVAL,
            "circuit_failure_threshold": CB_FAILURE_THRESHOLD,
            "circuit_recovery_timeout_seconds": CB_RECOVERY_TIMEOUT,
        },
    }
