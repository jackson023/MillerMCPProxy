from fastmcp import FastMCP

mcp = FastMCP("MillerTest")


@mcp.tool()
def ping() -> str:
    """Returns pong to verify connectivity."""
    return "pong — Miller IQ Platform is alive"
