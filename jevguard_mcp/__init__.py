"""
JevGuard MCP Server - Official Model Context Protocol runtime for JevGuard.
Provides deterministic evaluation, state pruning, certainty calibration,
and canonical cache fingerprinting over standard JSON-RPC 2.0 stdio transport.
"""

def __getattr__(name: str):
    if name in ("MCPServer", "run_server"):
        from .server import MCPServer, run_server
        return MCPServer if name == "MCPServer" else run_server
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
from .tools import (
    DeterministicCache,
    QuestionOptimizer,
    ResponseCalibrator,
    StatePruner,
    ToolRegistry,
    get_default_cache_db_path,
)

__version__ = "1.0.0"

__all__ = [
    "MCPServer",
    "run_server",
    "DeterministicCache",
    "QuestionOptimizer",
    "ResponseCalibrator",
    "StatePruner",
    "ToolRegistry",
    "get_default_cache_db_path",
    "__version__",
]
