"""
SENTRYLOG — Single-file SIEM for small teams — Sigma rules + multi-source ingest
Part of the Cognis Neural Suite by Cognis Digital.
https://cognis.digital · MIT License
"""
from sentrylog.core import scan, TOOL_NAME, TOOL_VERSION

__version__ = TOOL_VERSION
__author__ = "Cognis Digital"
__license__ = "MIT"
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION", "__version__"]
