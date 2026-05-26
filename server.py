from fastmcp import FastMCP
from typing import Any
import httpx
import json

mcp = FastMCP("MillerIQ")

MILLER_URL = "https://miller-mcp-db-v3-146372550543.us-central1.run.app/execute"
MILLER_KEY = "miller-techstack-2026"


@mcp.tool
def ping() -> str:
    """Returns pong to verify connectivity."""
    return "pong — Miller IQ Platform is alive"


@mcp.tool
async def meta_tool(tool_name: str, arguments: Any = None) -> str:
    """Execute any tool stored in the Postgres tool registry by name.

    This is the single entry point for all custom tools. When a user asks
    you to use a specific tool, call this with the tool's name and any
    required arguments.

    Args:
        tool_name: Name of the tool to run, exactly as stored in Postgres.
        arguments: Key/value pairs the tool needs. Can be a dict or a JSON
            string. Pass null or omit if none required.
    """
    if arguments is None:
        args = {}
    elif isinstance(arguments, str):
        try:
            args = json.loads(arguments)
        except (json.JSONDecodeError, TypeError):
            args = {}
    elif isinstance(arguments, dict):
        args = arguments
    else:
        args = {}

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            r = await client.post(
                MILLER_URL,
                json={"tool_name": tool_name, "arguments": args},
                headers={
                    "X-API-Key": MILLER_KEY,
                    "Content-Type": "application/json",
                },
            )
            if r.status_code != 200:
                return json.dumps({
                    "status": "error",
                    "http_code": r.status_code,
                    "body": r.text[:2000],
                })
            return r.text
    except httpx.TimeoutException:
        return json.dumps({"status": "error", "error": "Request timed out after 120s"})
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})
