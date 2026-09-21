"""
JevGuard MCP Server - JSON-RPC 2.0 stdio server implementation.
Complies with Model Context Protocol (MCP) specification 2024-11-05.
Uses strictly the Python standard library with zero external dependencies.
"""

import io
import json
import logging
import sys
import threading
from typing import Any, Dict, Optional, TextIO

from .tools import ToolRegistry, get_default_cache_db_path

logger = logging.getLogger("jevguard.mcp.server")
logger.addHandler(logging.NullHandler())

PROTOCOL_VERSION: str = "2024-11-05"
SERVER_NAME: str = "jevguard-mcp"
SERVER_VERSION: str = "1.0.0"


class MCPServer:
    """Standard JSON-RPC 2.0 stdio server implementing the Model Context Protocol."""

    def __init__(
        self,
        name: str = SERVER_NAME,
        version: str = SERVER_VERSION,
        cache_db_path: Optional[str] = None,
    ):
        self.name = name
        self.version = version
        self.protocol_version = PROTOCOL_VERSION
        self._lock = threading.RLock()
        self.registry = ToolRegistry(cache_db_path=cache_db_path)
        self.initialized = False
        self.running = False

    def handle_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Processes a single raw input line and returns an optional JSON-RPC response."""
        stripped = line.strip()
        if not stripped:
            return None

        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as err:
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
            msg_id = message.get("id")
            is_notification = "id" not in message or msg_id is None

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

            params = message.get("params", {})
            if params is None:
                params = {}
            elif not isinstance(params, (dict, list)):
                if is_notification:
                    return None
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: params must be an object or array",
                    },
                }

            # Handle notifications (no response permitted)
            if method in ("notifications/initialized", "initialized"):
                self.initialized = True
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
            elif method == "tools/list":
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
            result_text = json.dumps(result_data, indent=2, sort_keys=True, default=str)
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
                    "isError": False,
                },
            }
        except KeyError as err:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Error: Tool '{name}' not found. {err}",
                        }
                    ],
                    "isError": True,
                },
            }
        except Exception as err:
            err_dict = {
                "success": False,
                "error_type": type(err).__name__,
                "message": str(err),
                "fallback_action": "MANUAL_REVIEW_REQUIRED",
            }
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(err_dict, indent=2, sort_keys=True, default=str),
                        }
                    ],
                    "isError": False,
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
                    logger.debug("Input stream read error: %s", err)
                    break

                if not line:
                    break

                stripped = line.strip()
                if not stripped:
                    continue

                response = self.handle_line(line)
                if response is not None:
                    try:
                        serialized = json.dumps(
                            response,
                            separators=(",", ":"),
                            ensure_ascii=False,
                            default=str,
                        )
                        with self._lock:
                            output_stream.write(serialized + "\n")
                            output_stream.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        break
                    except Exception as err:
                        logger.debug("Output stream write error: %s", err)
                        break

        except KeyboardInterrupt:
            pass
        except Exception as err:
            logger.debug("Event loop unexpected exception: %s", err)
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
