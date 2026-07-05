"""IOCREP MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from iocrep.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-iocrep[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-iocrep[mcp]'")
        return 1
    app = FastMCP("iocrep")

    @app.tool()
    def iocrep_scan(target: str) -> str:
        """Score IOCs against offline reputation/allow lists with explainable verdicts. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
