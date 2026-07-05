"""YARAGEN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from yaragen.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-yaragen[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-yaragen[mcp]'")
        return 1
    app = FastMCP("yaragen")

    @app.tool()
    def yaragen_scan(target: str) -> str:
        """Generate candidate YARA rules from sample files/strings. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
