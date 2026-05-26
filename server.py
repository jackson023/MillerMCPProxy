from fastmcp import FastMCP
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
async def meta_tool(tool_name: str, arguments_json: str = "{}") -> str:
    """Execute any tool stored in the Postgres tool registry by name.

    This is the single entry point for all 1100+ custom tools.

    Args:
        tool_name: Name of the tool to run exactly as stored in Postgres.
        arguments_json: A JSON string of key/value pairs the tool needs.
            Examples: '{"module": "mcp"}' or '{"query": "health", "limit": 3}'
            Pass '{}' or omit if the tool needs no arguments.
    """
    try:
        arguments = json.loads(arguments_json) if arguments_json else {}
    except (json.JSONDecodeError, TypeError):
        return json.dumps({"status": "error", "error": f"Invalid JSON in arguments_json: {arguments_json}"})

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            r = await client.post(
                MILLER_URL,
                json={"tool_name": tool_name, "arguments": arguments},
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
        return json.dumps({"status": "error", "error": "Cloud Run request timed out after 120s"})
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})
