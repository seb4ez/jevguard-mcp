"""
JevGuard MCP Server - Official Model Context Protocol runtime for JevGuard.
Provides deterministic evaluation, state pruning, certainty calibration,
and canonical cache fingerprinting over standard JSON-RPC 2.0 stdio transport.
"""

from .server import MCPServer, run_server
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
