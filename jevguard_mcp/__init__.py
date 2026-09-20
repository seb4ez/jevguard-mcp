"""
JevGuard MCP Server - Official Model Context Protocol runtime for JevGuard.
Provides deterministic evaluation, state pruning, certainty calibration,
and canonical cache fingerprinting over standard JSON-RPC 2.0 stdio transport.
"""

from .server import MCPServer, run_server

__version__ = "1.0.0"

__all__ = [
    "MCPServer",
    "run_server",
    "__version__",
]
