import os

from intake_mcp.server import mcp

transport = os.getenv("MCP_TRANSPORT", "stdio")
if transport == "sse":
    mcp.settings.host = os.getenv("FASTMCP_HOST", "0.0.0.0")
    mcp.settings.port = int(os.getenv("FASTMCP_PORT", "8000"))

mcp.run(transport=transport)
