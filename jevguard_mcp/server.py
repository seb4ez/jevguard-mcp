"""
JevGuard MCP Server - JSON-RPC 2.0 stdio server implementation.
Complies with Model Context Protocol (MCP) specification 2024-11-05.
Uses strictly the Python standard library with zero external dependencies.
"""

import io
import json
import logging
import math
import os
import sys
import threading
from typing import Any, Dict, Optional, TextIO

try:
    from .tools import ToolRegistry, get_default_cache_db_path
except (ImportError, ValueError):
    from pathlib import Path
    pkg_root = str(Path(__file__).resolve().parent.parent)
    if pkg_root not in sys.path:
        sys.path.insert(0, pkg_root)
    from jevguard_mcp.tools import ToolRegistry, get_default_cache_db_path

logger = logging.getLogger("jevguard.mcp.server")
logger.addHandler(logging.NullHandler())

PROTOCOL_VERSION: str = "2024-11-05"
SERVER_NAME: str = "jevguard-mcp"
SERVER_VERSION: str = "1.1.0"


def _sanitize_floats(obj: Any) -> Any:
    """Recursively replaces NaN and Infinity with None to guarantee standard JSON compliance."""
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
        return obj
    elif isinstance(obj, dict):
        return {k: _sanitize_floats(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_sanitize_floats(item) for item in obj]
    return obj


class MCPServer:
    """Standard JSON-RPC 2.0 stdio server implementing the Model Context Protocol."""

    def __init__(
        self,
        name: str = SERVER_NAME,
        version: str = SERVER_VERSION,
        cache_db_path: Optional[str] = None,
        allow_test_mocks: Optional[bool] = None,
        initialized: bool = False,
    ):
        self.name = name
        self.version = version
        self.protocol_version = PROTOCOL_VERSION
        self._lock = threading.RLock()
        effective_cache_path = cache_db_path
        if effective_cache_path is None and os.environ.get("JEVGUARD_TEST_MODE") == "1":
            effective_cache_path = ":memory:"
        self.registry = ToolRegistry(cache_db_path=effective_cache_path, allow_test_mocks=allow_test_mocks)
        self._initialize_received: bool = initialized
        self.initialized = initialized
        self.running = False

    def handle_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Processes a single raw input line and returns an optional JSON-RPC response."""
        stripped = line.strip()
        if not stripped:
            return None

        try:
            payload = json.loads(stripped)
        except (json.JSONDecodeError, RecursionError, Exception) as err:
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": f"Parse error: invalid JSON payload: {err}",
                },
            }

        if not isinstance(payload, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: payload must be a JSON object",
                },
            }

        return self.handle_message(payload)

    def handle_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Handles a parsed JSON-RPC 2.0 message."""
        with self._lock:
            if message.get("jsonrpc") != "2.0":
                return {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {
                        "code": -32600,
                        "message": "Invalid Request: missing or invalid 'jsonrpc' field",
                    },
                }

            method = message.get("method")
            has_id = "id" in message
            msg_id = message.get("id")
            is_notification = not has_id

            if not isinstance(method, str):
                if is_notification:
                    return None
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32600,
                        "message": "Invalid Request: 'method' must be a string",
                    },
                }

            params = message.get("params")
            if params is None:
                params = {}
            elif isinstance(params, list):
                if is_notification:
                    return None
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: params must be a JSON object, arrays are unsupported",
                    },
                }
            elif not isinstance(params, dict):
                if is_notification:
                    return None
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: params must be an object",
                    },
                }

            # Handle notifications (no response permitted)
            if method in ("notifications/initialized", "initialized"):
                if self._initialize_received:
                    self.initialized = True
                else:
                    logger.warning("Received 'notifications/initialized' before 'initialize' request was completed.")
                return None

            if method in ("notifications/cancelled", "cancelled"):
                return None

            if is_notification:
                return None

            # Handle request methods with mandatory response
            if method == "initialize":
                return self._handle_initialize(msg_id, params)
            elif method == "ping":
                return self._handle_ping(msg_id)

            if not self.initialized:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32002,
                        "message": f"Server not initialized: must call 'initialize' before '{method}'",
                    },
                }

            if method == "tools/list":
                return self._handle_tools_list(msg_id)
            elif method == "tools/call":
                return self._handle_tools_call(msg_id, params)
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: '{method}'",
                    },
                }

    def _handle_initialize(self, msg_id: Any, params: Any) -> Dict[str, Any]:
        if not isinstance(params, dict):
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32602,
                    "message": "Invalid params: initialize parameters must be a JSON object",
                },
            }
        protocol_version = params.get("protocolVersion")
        if not protocol_version or not isinstance(protocol_version, str):
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32602,
                    "message": "Invalid params: 'protocolVersion' string is required for initialize",
                },
            }
        client_info = params.get("clientInfo")
        if not isinstance(client_info, dict) or not str(client_info.get("name", "")).strip():
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32602,
                    "message": "Invalid params: 'clientInfo' object with non-empty 'name' is required for initialize",
                },
            }

        self._initialize_received = True
        self.initialized = True
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": self.protocol_version,
                "capabilities": {
                    "tools": {
                        "listChanged": False,
                    }
                },
                "serverInfo": {
                    "name": self.name,
                    "version": self.version,
                },
            },
        }

    def _handle_ping(self, msg_id: Any) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {},
        }

    def _handle_tools_list(self, msg_id: Any) -> Dict[str, Any]:
        tools = self.registry.get_definitions()
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": tools,
            },
        }

    def _handle_tools_call(self, msg_id: Any, params: Any) -> Dict[str, Any]:
        if not isinstance(params, dict):
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32602,
                    "message": "Invalid params: 'params' must be a dictionary",
                },
            }

        name = params.get("name")
        if not isinstance(name, str) or not name.strip():
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32602,
                    "message": "Invalid params: missing or empty tool 'name'",
                },
            }

        arguments = params.get("arguments", {})
        if arguments is None:
            arguments = {}
        elif not isinstance(arguments, dict):
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32602,
                    "message": "Invalid params: tool 'arguments' must be an object",
                },
            }

        try:
            result_data = self.registry.execute_tool(name, arguments)
            if not result_data.get("success", True) and result_data.get("error_type") == "ValidationError":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32602,
                        "message": f"Invalid params: {result_data.get('message')}",
                    },
                }

            clean_result_data = _sanitize_floats(result_data)
            result_text = json.dumps(clean_result_data, indent=2, sort_keys=True, allow_nan=False, default=str)
            is_error = not result_data.get("success", True) or result_data.get("status") == "error"
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": result_text,
                        }
                    ],
                    "isError": is_error,
                },
            }
        except KeyError as err:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found / Unknown tool: '{name}' ({err})",
                },
            }
        except (ValueError, TypeError) as err:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32602,
                    "message": f"Invalid params: {err}",
                },
            }
        except Exception as err:
            err_dict = {
                "status": "error",
                "success": False,
                "error_type": type(err).__name__,
                "message": str(err),
                "verdict": "MANUAL_REVIEW_REQUIRED",
                "fallback_action": "MANUAL_REVIEW_REQUIRED",
            }
            clean_err_dict = _sanitize_floats(err_dict)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(clean_err_dict, indent=2, sort_keys=True, allow_nan=False, default=str),
                        }
                    ],
                    "isError": True,
                },
            }

    def run_stdio(
        self,
        input_stream: Optional[TextIO] = None,
        output_stream: Optional[TextIO] = None,
    ) -> None:
        """Runs the blocking stdio event loop processing JSON-RPC messages."""
        if input_stream is None:
            if hasattr(sys.stdin, "reconfigure"):
                try:
                    sys.stdin.reconfigure(encoding="utf-8")
                except Exception:
                    pass
            input_stream = sys.stdin

        if output_stream is None:
            if hasattr(sys.stdout, "reconfigure"):
                try:
                    sys.stdout.reconfigure(encoding="utf-8")
                except Exception:
                    pass
            output_stream = sys.stdout

        with self._lock:
            self.running = True

        try:
            while True:
                with self._lock:
                    if not self.running:
                        break

                try:
                    line = input_stream.readline()
                except (EOFError, KeyboardInterrupt):
                    break
                except (BrokenPipeError, ConnectionResetError):
                    break
                except Exception as err:
                    logger.error("Input stream read error: %s", err, exc_info=True)
                    break

                if not line:
                    break

                MAX_LINE_BYTES = 10 * 1024 * 1024
                if len(line) > MAX_LINE_BYTES:
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32700,
                            "message": f"Parse error: input line exceeded {MAX_LINE_BYTES} bytes limit",
                        },
                    }
                    with self._lock:
                        output_stream.write(json.dumps(err_resp, separators=(",", ":")) + "\n")
                        output_stream.flush()
                    continue

                stripped = line.strip()
                if not stripped:
                    continue

                response = self.handle_line(line)
                if response is not None:
                    try:
                        clean_response = _sanitize_floats(response)
                        serialized = json.dumps(
                            clean_response,
                            separators=(",", ":"),
                            ensure_ascii=False,
                            allow_nan=False,
                            default=str,
                        )
                        with self._lock:
                            output_stream.write(serialized + "\n")
                            output_stream.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        break
                    except Exception as err:
                        logger.error("Output stream serialization/write error: %s", err, exc_info=True)
                        fallback_err = {
                            "jsonrpc": "2.0",
                            "id": response.get("id") if isinstance(response, dict) else None,
                            "error": {
                                "code": -32603,
                                "message": f"Internal JSON serialization error: {err}",
                            },
                        }
                        try:
                            with self._lock:
                                output_stream.write(json.dumps(fallback_err, separators=(",", ":")) + "\n")
                                output_stream.flush()
                        except Exception:
                            break

        except KeyboardInterrupt:
            pass
        except Exception as err:
            logger.error("Event loop unexpected exception: %s", err, exc_info=True)
        finally:
            with self._lock:
                self.running = False
                try:
                    self.registry.close()
                except Exception as err:
                    logger.debug("Error closing registry: %s", err)


def run_server() -> None:
    """Entry point creating and executing the MCP server over standard stdio."""
    try:
        logging.basicConfig(
            stream=sys.stderr,
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            force=True,
        )
    except TypeError:
        logging.basicConfig(
            stream=sys.stderr,
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )

    for handler in logging.root.handlers:
        if getattr(handler, "stream", None) is sys.stdout:
            handler.stream = sys.stderr

    server = MCPServer()
    server.run_stdio()


def main() -> None:
    run_server()


if __name__ == "__main__":
    main()
