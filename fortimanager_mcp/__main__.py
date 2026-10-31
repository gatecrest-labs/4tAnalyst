import os

from fortimanager_mcp.server import mcp

transport = os.getenv("MCP_TRANSPORT", "stdio")
if transport == "sse":
    mcp.run(
        transport=transport,
        host=os.getenv("FASTMCP_HOST", "0.0.0.0"),
        port=int(os.getenv("FASTMCP_PORT", "8000")),
    )
else:
    mcp.run(transport=transport)
