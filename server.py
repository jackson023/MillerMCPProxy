from fastmcp import FastMCP
import httpx

mcp = FastMCP("MillerIQ")

MILLER_URL = "https://miller-mcp-db-v3-146372550543.us-central1.run.app/execute"
MILLER_KEY = "miller-techstack-2026"


@mcp.tool()
async def meta_tool(tool_name: str, arguments: dict = None) -> str:
    """Execute any tool stored in the Postgres tool registry by name.
    This is the single entry point for all custom tools.
    Args: tool_name: Name of the tool to run, exactly as stored in Postgres.
    arguments: Key/value pairs the tool needs (omit or pass null if none required).
    Returns the tool's result directly."""
    async with httpx.AsyncClient(timeout=120.0) as client:
        r = await client.post(
            MILLER_URL,
            json={"tool_name": tool_name, "arguments": arguments or {}},
            headers={
                "X-API-Key": MILLER_KEY,
                "Content-Type": "application/json",
            },
        )
        return r.text
