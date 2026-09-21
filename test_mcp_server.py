"""
test_mcp_server.py - Comprehensive Unit and Stdio Test Suite for JevGuard MCP Server.
Implements 100% Python standard library (unittest, io, json, tempfile, os).
Strictly adheres to Humanizer English standards.
"""

import ast
import io
import json
import math
import os
import pathlib
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest import mock

# Enable test mode for test suite execution to permit test mock answers
os.environ["JEVGUARD_TEST_MODE"] = "1"

from jevguard_mcp.server import MCPServer
from jevguard_mcp.tools import (
    DeterministicCache,
    ESCAPE_OPTION_KEY,
    QuestionOptimizer,
    ResponseCalibrator,
    StatePruner,
    ToolRegistry,
    get_default_cache_db_path,
)


class TestProtocolHandshake(unittest.TestCase):
    """Verifies MCP JSON-RPC 2.0 handshake and basic protocol operations."""

    def setUp(self):
        self.server = MCPServer()

    def test_initialize_request(self):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
        }
        response = self.server.handle_message(request)
        self.assertIsNotNone(response)
        self.assertEqual(response.get("jsonrpc"), "2.0")
        self.assertEqual(response.get("id"), 1)

        result = response.get("result", {})
        self.assertEqual(result.get("protocolVersion"), "2024-11-05")
        self.assertEqual(result.get("serverInfo", {}).get("name"), "jevguard-mcp")
        self.assertEqual(result.get("serverInfo", {}).get("version"), "1.0.0")
        self.assertIn("tools", result.get("capabilities", {}))

    def test_notifications_initialized_produces_no_response(self):
        notification = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        response = self.server.handle_message(notification)
        self.assertIsNone(response)
        self.assertTrue(self.server.initialized)

        legacy_notification = {
            "jsonrpc": "2.0",
            "method": "initialized",
        }
        response_legacy = self.server.handle_message(legacy_notification)
        self.assertIsNone(response_legacy)

    def test_ping_request(self):
        request = {
            "jsonrpc": "2.0",
            "id": "ping-42",
            "method": "ping",
        }
        response = self.server.handle_message(request)
        self.assertIsNotNone(response)
        self.assertEqual(response.get("id"), "ping-42")
        self.assertEqual(response.get("result"), {})

    def test_unknown_method_returns_error(self):
        request = {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "non_existent_method",
        }
        response = self.server.handle_message(request)
        self.assertIsNotNone(response)
        self.assertEqual(response.get("id"), 99)
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], -32601)

    def test_parse_error_on_malformed_json_string(self):
        raw_line = "{malformed json input"
        response = self.server.handle_line(raw_line)
        self.assertIsNotNone(response)
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], -32700)

    def test_invalid_request_missing_jsonrpc_version(self):
        request = {"id": 1, "method": "ping"}
        response = self.server.handle_message(request)
        self.assertIsNotNone(response)
        self.assertEqual(response["error"]["code"], -32600)


class TestToolsList(unittest.TestCase):
    """Verifies tool discovery and schema correctness."""

    def setUp(self):
        self.server = MCPServer()

    def test_tools_list_returns_four_tools(self):
        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
        }
        response = self.server.handle_message(request)
        self.assertIsNotNone(response)
        tools = response.get("result", {}).get("tools", [])
        self.assertEqual(len(tools), 7)

        tool_names = {t["name"] for t in tools}
        expected_names = {
            "jevguard_evaluate",
            "jevguard_calibrate",
            "jevguard_prune_state",
            "jevguard_cache_fingerprint",
            "evaluate_command_safety",
            "verify_code_patch",
            "evaluate_decision",
        }
        self.assertEqual(tool_names, expected_names)

        for tool in tools:
            self.assertIn("name", tool)
            self.assertIn("description", tool)
            self.assertIn("inputSchema", tool)
            self.assertEqual(tool["inputSchema"].get("type"), "object")
            self.assertIn("properties", tool["inputSchema"])


class TestStatePruner(unittest.TestCase):
    """Verifies state pruning and circular reference detection."""

    def test_prune_nulls_and_empty_values(self):
        state = {
            "user": "alice",
            "empty_str": "",
            "none_val": None,
            "nested": {
                "count": 42,
                "deep_empty": {},
                "deep_null": None,
            },
        }
        pruned = StatePruner.prune(state)
        self.assertEqual(pruned, {"user": "alice", "nested": {"count": 42}})

    def test_prune_whitespace_normalization(self):
        text = "  multiple   spaces   and   tabs  "
        pruned = StatePruner.prune(text)
        self.assertEqual(pruned, "multiple spaces and tabs")

    def test_prune_preserves_multiline_diffs_and_code_indentation(self):
        patch = (
            "--- a/calculator.py\n"
            "+++ b/calculator.py\n"
            "@@ -1,4 +1,4 @@\n"
            " def add(a: int, b: int) -> int:\n"
            "-    return a - b\n"
            "+    return a + b"
        )
        pruned = StatePruner.prune(patch)
        self.assertEqual(pruned, patch)

    def test_circular_reference_protection(self):
        cyclic = {"name": "cyclic_node"}
        cyclic["self_ref"] = cyclic
        pruned = StatePruner.prune(cyclic)
        self.assertEqual(pruned["self_ref"], "<cyclic_ref>")
        self.assertEqual(pruned["name"], "cyclic_node")

    def test_list_positions_preserved_by_default(self):
        items = ["first", "", None, "fourth"]
        pruned = StatePruner.prune(items, prune_lists=False)
        self.assertEqual(len(pruned), 4)
        self.assertEqual(pruned[0], "first")
        self.assertEqual(pruned[1], "")
        self.assertIsNone(pruned[2])
        self.assertEqual(pruned[3], "fourth")

    def test_list_positions_stripped_when_prune_lists_true(self):
        items = ["first", "", None, "fourth"]
        pruned = StatePruner.prune(items, prune_lists=True)
        self.assertEqual(pruned, ["first", "fourth"])

    def test_heterogeneous_types_pruned(self):
        state = {
            "tags": {"python", "mcp"},
            "coords": (12.34, 56.78),
            "nan_val": float("nan"),
            "inf_val": float("inf"),
            100: "numeric_key",
        }
        pruned = StatePruner.prune(state)
        self.assertIn("tags", pruned)
        self.assertEqual(pruned["tags"], ["mcp", "python"])
        self.assertEqual(pruned["coords"], (12.34, 56.78))
        self.assertNotIn("nan_val", pruned)
        self.assertNotIn("inf_val", pruned)
        self.assertIn("100", pruned)


class TestCacheFingerprint(unittest.TestCase):
    """Verifies canonical SHA-256 fingerprinting and volatile key masking."""

    def test_key_ordering_invariance(self):
        state_a = {"alpha": 1, "beta": 2, "gamma": 3}
        state_b = {"gamma": 3, "alpha": 1, "beta": 2}
        fp_a = DeterministicCache.compute_fingerprint("jev-latest", state_a)
        fp_b = DeterministicCache.compute_fingerprint("jev-latest", state_b)
        self.assertEqual(fp_a, fp_b)

    def test_volatile_key_masking(self):
        state_1 = {
            "user_id": "usr_100",
            "created_at": 1726780000,
            "trace_id": "trace-abc-001",
            "request-id": "req-999",
            "action": "execute",
        }
        state_2 = {
            "user_id": "usr_100",
            "created_at": 1726799999,
            "trace_id": "trace-xyz-999",
            "request-id": "req-000",
            "action": "execute",
        }
        fp_1 = DeterministicCache.compute_fingerprint("jev-latest", state_1)
        fp_2 = DeterministicCache.compute_fingerprint("jev-latest", state_2)
        self.assertEqual(fp_1, fp_2)

    def test_custom_ignore_keys(self):
        state_1 = {"user": "bob", "temp_session": "sess_1"}
        state_2 = {"user": "bob", "temp_session": "sess_2"}
        fp_1 = DeterministicCache.compute_fingerprint(
            "jev-latest", state_1, ignore_keys=["temp_session"]
        )
        fp_2 = DeterministicCache.compute_fingerprint(
            "jev-latest", state_2, ignore_keys=["temp_session"]
        )
        self.assertEqual(fp_1, fp_2)


class TestResponseCalibrator(unittest.TestCase):
    """Verifies certainty calibration, ambiguity detection, and dispersion gaps."""

    def setUp(self):
        self.calibrator = ResponseCalibrator()

    def test_choice_low_confidence_flagged(self):
        answers = {
            "decision": {
                "type": "choice",
                "choice": "opt_a",
                "confidence": 0.35,
                "probabilities": {"opt_a": 0.35, "opt_b": 0.33, "opt_c": 0.32},
            }
        }
        calibrated, summary = self.calibrator.calibrate(answers)
        self.assertTrue(summary["has_ambiguity"])
        self.assertEqual(summary["verdict"], "AMBIGUOUS_STATE")
        self.assertIn("decision", summary["ambiguous_questions"])
        self.assertIn("low_confidence", calibrated["decision"]["calibration"]["reasons"])

    def test_choice_flat_distribution_flagged(self):
        answers = {
            "route": {
                "type": "choice",
                "choice": "opt_a",
                "confidence": 0.45,
                "probabilities": {"opt_a": 0.45, "opt_b": 0.42, "opt_c": 0.13},
            }
        }
        calibrated, summary = self.calibrator.calibrate(answers)
        self.assertTrue(summary["has_ambiguity"])
        self.assertEqual(summary["verdict"], "AMBIGUOUS_STATE")
        self.assertIn("flat_distribution", calibrated["route"]["calibration"]["reasons"])

    def test_choice_confident_distribution_accepted(self):
        answers = {
            "intent": {
                "type": "choice",
                "choice": "billing",
                "confidence": 0.90,
                "probabilities": {"billing": 0.90, "support": 0.08, "sales": 0.02},
            }
        }
        calibrated, summary = self.calibrator.calibrate(answers)
        self.assertFalse(summary["has_ambiguity"])
        self.assertEqual(summary["verdict"], "CONFIDENT")
        self.assertEqual(len(summary["ambiguous_questions"]), 0)

    def test_score_flat_distribution_flagged(self):
        answers = {
            "severity": {
                "type": "score",
                "score": 2,
                "confidence": 0.50,
                "probabilities": {"1": 0.05, "2": 0.49, "3": 0.46},
            }
        }
        calibrated, summary = self.calibrator.calibrate(answers)
        self.assertTrue(summary["has_ambiguity"])
        self.assertIn("flat_distribution", calibrated["severity"]["calibration"]["reasons"])

    def test_noul_boundary_uncertainty_flagged(self):
        answers = {
            "is_anomaly": {
                "type": "noul",
                "noul": 0.54,
            }
        }
        calibrated, summary = self.calibrator.calibrate(answers)
        self.assertTrue(summary["has_ambiguity"])
        self.assertIn("boundary_uncertainty", calibrated["is_anomaly"]["calibration"]["reasons"])


class TestToolsCallExecution(unittest.TestCase):
    """Verifies end-to-end tool calls via JSON-RPC tools/call."""

    def setUp(self):
        self.server = MCPServer()
        self.server.registry.cache.clear()

    def tearDown(self):
        self.server.registry.close()

    def test_call_prune_state_tool(self):
        call_msg = {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "jevguard_prune_state",
                "arguments": {
                    "state": {"name": "Alice", "dropped": None, "empty": ""},
                    "prune_lists": False,
                },
            },
        }
        resp = self.server.handle_message(call_msg)
        self.assertIsNotNone(resp)
        self.assertFalse(resp.get("result", {}).get("isError"))
        content = resp["result"]["content"][0]["text"]
        data = json.loads(content)
        self.assertEqual(data["pruned_state"], {"name": "Alice"})
        self.assertGreater(data["estimated_tokens"], 0)

    def test_call_cache_fingerprint_tool(self):
        call_msg = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "jevguard_cache_fingerprint",
                "arguments": {
                    "state": {"task": "classify", "timestamp": 12345},
                    "model": "jev-latest",
                },
            },
        }
        resp = self.server.handle_message(call_msg)
        self.assertIsNotNone(resp)
        self.assertFalse(resp.get("result", {}).get("isError"))
        data = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(len(data["fingerprint"]), 64)
        self.assertIn("timestamp", data["masked_volatile_keys"])

    def test_call_calibrate_tool(self):
        call_msg = {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "jevguard_calibrate",
                "arguments": {
                    "answers": {
                        "category": {
                            "type": "choice",
                            "choice": "tech",
                            "confidence": 0.35,
                            "probabilities": {"tech": 0.35, "sales": 0.33, "billing": 0.32},
                        }
                    }
                },
            },
        }
        resp = self.server.handle_message(call_msg)
        self.assertIsNotNone(resp)
        self.assertFalse(resp.get("result", {}).get("isError"))
        data = json.loads(resp["result"]["content"][0]["text"])
        self.assertIn("summary", data)
        self.assertEqual(data["summary"]["verdict"], "AMBIGUOUS_STATE")

    def test_call_evaluate_tool_with_mock_answers_and_cache(self):
        state = {"order_id": "ord_101", "created_at": 1726700000}
        questions = {
            "classification": {
                "type": "choice",
                "instructions": "Determine priority",
                "criteria": {"urgent": "Immediate action", "standard": "Normal queue"},
            }
        }
        mock_answers = {
            "classification": {
                "type": "choice",
                "choice": "urgent",
                "confidence": 0.95,
                "probabilities": {"urgent": 0.95, "standard": 0.05},
            }
        }

        call_msg = {
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "jevguard_evaluate",
                "arguments": {
                    "state": state,
                    "questions": questions,
                    "mock_answers": mock_answers,
                },
            },
        }

        resp1 = self.server.handle_message(call_msg)
        data1 = json.loads(resp1["result"]["content"][0]["text"])
        self.assertTrue(data1["success"])
        self.assertFalse(data1["cached"])
        self.assertEqual(data1["calibration"]["verdict"], "CONFIDENT")
        self.assertIn(ESCAPE_OPTION_KEY, data1["optimization"]["injected_escapes"].get("classification", ""))

        # Second call with identical state should hit cache (0 tokens consumed)
        call_msg["id"] = 14
        resp2 = self.server.handle_message(call_msg)
        data2 = json.loads(resp2["result"]["content"][0]["text"])
        self.assertTrue(data2["success"])
        self.assertTrue(data2["cached"])
        self.assertEqual(data2["telemetry"]["tokens_consumed"], 0)
        self.assertEqual(data2["cache_fingerprint"], data1["cache_fingerprint"])

        # Third call with updated volatile timestamp should still hit cache
        state_updated_time = {"order_id": "ord_101", "created_at": 1726999999}
        call_msg["id"] = 15
        call_msg["params"]["arguments"]["state"] = state_updated_time
        resp3 = self.server.handle_message(call_msg)
        data3 = json.loads(resp3["result"]["content"][0]["text"])
        self.assertTrue(data3["cached"])
        self.assertEqual(data3["cache_fingerprint"], data1["cache_fingerprint"])

    def test_call_unknown_tool_returns_error(self):
        call_msg = {
            "jsonrpc": "2.0",
            "id": 16,
            "method": "tools/call",
            "params": {"name": "non_existent_tool", "arguments": {}},
        }
        resp = self.server.handle_message(call_msg)
        self.assertIsNotNone(resp)
        self.assertTrue(resp.get("result", {}).get("isError"))
        self.assertIn("not found", resp["result"]["content"][0]["text"].lower())


class TestServerStdioPipeline(unittest.TestCase):
    """Simulates full stdio streaming and JSON-RPC session exchange."""

    def test_complete_stdio_stream(self):
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "jevguard_prune_state",
                    "arguments": {"state": {"hello": "world", "empty": None}},
                },
            },
            {"jsonrpc": "2.0", "id": 4, "method": "ping"},
        ]

        raw_input = "\n".join(json.dumps(r) for r in requests) + "\n"
        input_stream = io.StringIO(raw_input)
        output_stream = io.StringIO()

        server = MCPServer()
        server.run_stdio(input_stream=input_stream, output_stream=output_stream)

        output_lines = [
            line.strip() for line in output_stream.getvalue().split("\n") if line.strip()
        ]
        # 4 responses expected (initialize, tools/list, tools/call, ping; notification yields nothing)
        self.assertEqual(len(output_lines), 4)

        for line in output_lines:
            parsed = json.loads(line)
            self.assertEqual(parsed.get("jsonrpc"), "2.0")
            self.assertIn("id", parsed)




class TestDeterministicCacheLRU(unittest.TestCase):
    """Verifies LRU memory eviction ordering and hit promotion."""

    def test_lru_capacity_eviction_and_hit_promotion(self):
        cache = DeterministicCache(db_path=":memory:", max_memory_items=2)
        cache.put("fp_1", "jev-latest", {"data": 1})
        cache.put("fp_2", "jev-latest", {"data": 2})

        # Access fp_1 to promote it to MRU position
        res1 = cache.get("fp_1")
        self.assertEqual(res1, {"data": 1})

        # Inserting fp_3 should evict fp_2 (since fp_1 was promoted)
        cache.put("fp_3", "jev-latest", {"data": 3})

        self.assertIn("fp_1", cache._memory_lru)
        self.assertIn("fp_3", cache._memory_lru)
        self.assertNotIn("fp_2", cache._memory_lru)
        cache.close()

    def test_volatile_key_masking_handles_nan_and_inf(self):
        state = {
            "valid": 100,
            "nan_val": float("nan"),
            "inf_val": float("inf"),
            "timestamp": 123456,
        }
        stripped = DeterministicCache._strip_volatile_keys(state, set(["timestamp"]))
        self.assertEqual(stripped["valid"], 100)
        self.assertIsNone(stripped["nan_val"])
        self.assertIsNone(stripped["inf_val"])
        self.assertNotIn("timestamp", stripped)


class TestFingerprintParity(unittest.TestCase):
    """Verifies fingerprint parity between jevguard_cache_fingerprint and jevguard_evaluate."""

    def setUp(self):
        self.registry = ToolRegistry()

    def test_cache_fingerprint_matches_evaluate_fingerprint(self):
        state = {"user_id": "usr_42", "timestamp": 1726700000}
        questions = {
            "intent": {
                "type": "choice",
                "instructions": "Identify intent",
                "criteria": {"billing": "Billing inquiry", "support": "Tech support"},
            }
        }

        fp_res = self.registry.execute_tool(
            "jevguard_cache_fingerprint",
            {
                "state": state,
                "questions": questions,
                "model": "jev-latest",
                "auto_inject_escapes": True,
            },
        )

        eval_res = self.registry.execute_tool(
            "jevguard_evaluate",
            {
                "state": state,
                "questions": questions,
                "model": "jev-latest",
                "auto_inject_escapes": True,
                "mock_answers": {
                    "intent": {
                        "type": "choice",
                        "choice": "billing",
                        "confidence": 0.95,
                        "probabilities": {"billing": 0.95, "support": 0.05},
                    }
                },
            },
        )

        self.assertEqual(fp_res["fingerprint"], eval_res["cache_fingerprint"])


class TestCalibratorEdgeCases(unittest.TestCase):
    """Verifies robust calibration against NaN and Inf probability payloads."""

    def setUp(self):
        self.calibrator = ResponseCalibrator()

    def test_choice_with_nan_probability_flagged(self):
        answers = {
            "q1": {
                "type": "choice",
                "choice": "opt_a",
                "confidence": 0.90,
                "probabilities": {"opt_a": float("nan"), "opt_b": 0.10},
            }
        }
        calibrated, summary = self.calibrator.calibrate(answers)
        self.assertTrue(summary["has_ambiguity"])
        self.assertIn("invalid_probability", calibrated["q1"]["calibration"]["reasons"])

    def test_score_with_nan_confidence_flagged(self):
        answers = {
            "q1": {
                "type": "score",
                "score": 3,
                "confidence": float("nan"),
                "probabilities": {"1": 0.1, "3": 0.9},
            }
        }
        calibrated, summary = self.calibrator.calibrate(answers)
        self.assertTrue(summary["has_ambiguity"])
        self.assertIn("invalid_probability", calibrated["q1"]["calibration"]["reasons"])

    def test_noul_with_nan_or_inf_flagged(self):
        answers = {
            "q_nan": {"type": "noul", "noul": float("nan")},
            "q_inf": {"type": "noul", "noul": float("inf")},
        }
        calibrated, summary = self.calibrator.calibrate(answers)
        self.assertTrue(summary["has_ambiguity"])
        self.assertIn("invalid_probability", calibrated["q_nan"]["calibration"]["reasons"])
        self.assertIn("invalid_probability", calibrated["q_inf"]["calibration"]["reasons"])


class TestQuestionOptimizerEdgeCases(unittest.TestCase):
    """Verifies robustness of QuestionOptimizer against edge-case definitions."""

    def setUp(self):
        self.optimizer = QuestionOptimizer()

    def test_score_question_with_none_criteria(self):
        questions = {
            "q_score": {
                "type": "score",
                "instructions": "Rate quality",
                "criteria": None,
            }
        }
        wire_questions, _ = self.optimizer.normalize_questions(questions)
        self.assertEqual(wire_questions["q_score"]["criteria"], [])

    def test_auto_inject_escape_override(self):
        questions = {
            "q_choice": {
                "type": "choice",
                "instructions": "Select option",
                "criteria": {"a": "Alpha", "b": "Beta"},
                "auto_inject_escape": False,
            }
        }
        wire_questions, injected = self.optimizer.normalize_questions(questions, auto_inject_escapes=True)
        self.assertNotIn("q_choice", injected)
        self.assertNotIn(ESCAPE_OPTION_KEY, wire_questions["q_choice"]["criteria"])


class TestAuditPoint1NoPrintAndStderrLogging(unittest.TestCase):
    """Point 1: Verifies that print() is poisoned (never used) and logging uses sys.stderr exclusively."""

    def test_no_print_in_jevguard_mcp_package(self):
        package_dir = pathlib.Path(__file__).parent / "jevguard_mcp"
        python_files = list(package_dir.glob("*.py"))
        self.assertGreater(len(python_files), 0)

        for py_file in python_files:
            with open(py_file, "r", encoding="utf-8") as f:
                source = f.read()
            tree = ast.parse(source, filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id == "print":
                        self.fail(f"Found forbidden print() call in {py_file.name} at line {node.lineno}")

    def test_server_run_stdio_writes_only_valid_json_rpc(self):
        server = MCPServer(cache_db_path=":memory:")
        input_stream = io.StringIO('{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
        output_stream = io.StringIO()

        server.run_stdio(input_stream=input_stream, output_stream=output_stream)
        raw_output = output_stream.getvalue().strip()
        self.assertTrue(raw_output)
        lines = raw_output.splitlines()
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertEqual(parsed.get("jsonrpc"), "2.0")
        self.assertEqual(parsed.get("id"), 1)

    def test_logging_configuration_strictly_targets_stderr(self):
        from jevguard_mcp.server import run_server
        with mock.patch("jevguard_mcp.server.MCPServer") as mock_server_cls:
            mock_server_instance = mock.MagicMock()
            mock_server_cls.return_value = mock_server_instance
            import logging
            run_server()
            for handler in logging.root.handlers:
                stream = getattr(handler, "stream", None)
                if stream is not None:
                    self.assertIsNot(stream, sys.stdout)


class TestAuditPoint2MissingEnvVariables(unittest.TestCase):
    """Point 2: Missing TYPESAFE_API_KEY environment variable handling."""

    def setUp(self):
        self.env_patcher = mock.patch.dict(os.environ, {}, clear=True)
        self.env_patcher.start()
        self.server = MCPServer(cache_db_path=":memory:", allow_test_mocks=True)

    def tearDown(self):
        self.env_patcher.stop()

    def test_handshake_and_listing_without_api_key(self):
        resp_init = self.server.handle_message({
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}
        })
        self.assertEqual(resp_init["result"]["serverInfo"]["name"], "jevguard-mcp")

        resp_notif = self.server.handle_message({
            "jsonrpc": "2.0", "method": "notifications/initialized"
        })
        self.assertIsNone(resp_notif)

        resp_ping = self.server.handle_message({
            "jsonrpc": "2.0", "id": 2, "method": "ping"
        })
        self.assertEqual(resp_ping["result"], {})

        resp_tools = self.server.handle_message({
            "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}
        })
        self.assertEqual(len(resp_tools["result"]["tools"]), 7)

    def test_evaluate_without_api_key_returns_structured_error(self):
        state = {"order_id": "ord_100"}
        questions = {
            "q1": {
                "type": "choice",
                "instructions": "Determine priority",
                "criteria": {"high": "High priority", "low": "Low priority"},
            }
        }

        call_msg = {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "jevguard_evaluate",
                "arguments": {
                    "state": state,
                    "questions": questions,
                },
            },
        }

        resp = self.server.handle_message(call_msg)
        self.assertIsNotNone(resp)
        self.assertFalse(resp.get("result", {}).get("isError", True))
        content = json.loads(resp["result"]["content"][0]["text"])

        self.assertFalse(content["success"])
        self.assertEqual(content["error"], "TYPESAFE_API_KEY not configured in MCP settings or environment")
        self.assertIn("cache_fingerprint", content)
        self.assertIn("wire_payload", content)
        self.assertIn("optimization", content)

    def test_local_tools_and_cache_hits_work_100_percent_offline(self):
        res_prune = self.server.registry.execute_tool(
            "jevguard_prune_state",
            {"state": {"a": 1, "b": None, "c": ""}}
        )
        self.assertEqual(res_prune["pruned_state"], {"a": 1})

        res_calib = self.server.registry.execute_tool(
            "jevguard_calibrate",
            {
                "answers": {
                    "q1": {
                        "type": "choice",
                        "choice": "yes",
                        "confidence": 0.95,
                        "probabilities": {"yes": 0.95, "no": 0.05},
                    }
                }
            }
        )
        self.assertEqual(res_calib["summary"]["verdict"], "CONFIDENT")

        res_fp = self.server.registry.execute_tool(
            "jevguard_cache_fingerprint",
            {"state": {"user": "alice"}}
        )
        self.assertIn("fingerprint", res_fp)

        # First prime cache with mock_answers
        prime_res = self.server.registry.execute_tool(
            "jevguard_evaluate",
            {
                "state": {"user": "offline_user"},
                "questions": {"q": {"type": "choice", "instructions": "test", "criteria": {"a": "A", "b": "B"}}},
                "mock_answers": {"q": {"type": "choice", "choice": "a", "confidence": 0.99, "probabilities": {"a": 0.99, "b": 0.01}}},
            }
        )
        self.assertTrue(prime_res["success"])
        self.assertFalse(prime_res["cached"])

        # Second call with NO mock_answers and NO api_key must hit cache cleanly and succeed offline
        cached_res = self.server.registry.execute_tool(
            "jevguard_evaluate",
            {
                "state": {"user": "offline_user"},
                "questions": {"q": {"type": "choice", "instructions": "test", "criteria": {"a": "A", "b": "B"}}},
            }
        )
        self.assertTrue(cached_res["success"])
        self.assertTrue(cached_res["cached"])
        self.assertEqual(cached_res["telemetry"]["mode"], "deterministic_cache_hit")


class TestAuditPoint3CacheDatabasePath(unittest.TestCase):
    """Point 3: Verifies default SQLite cache path in ~/.cache/jevguard and memory fallback."""

    def test_default_cache_db_path_resolution(self):
        default_path = get_default_cache_db_path()
        expected_base = pathlib.Path.home() / ".cache" / "jevguard" / "decision_cache.db"
        self.assertEqual(pathlib.Path(default_path), expected_base.resolve())

    def test_memory_path_preserved(self):
        self.assertEqual(get_default_cache_db_path(":memory:"), ":memory:")

    def test_relative_path_resolved_inside_cache_directory(self):
        resolved = get_default_cache_db_path("my_cache.db")
        expected = pathlib.Path.home() / ".cache" / "jevguard" / "my_cache.db"
        self.assertEqual(pathlib.Path(resolved), expected.resolve())
        self.assertFalse(os.path.exists("my_cache.db"))

    def test_env_override_supported(self):
        with mock.patch.dict(os.environ, {"JEVGUARD_CACHE_PATH": "env_override.db"}):
            resolved = get_default_cache_db_path()
            expected = pathlib.Path.home() / ".cache" / "jevguard" / "env_override.db"
            self.assertEqual(pathlib.Path(resolved), expected.resolve())

        with mock.patch.dict(os.environ, {"JEVGUARD_CACHE_PATH": ":memory:"}):
            self.assertEqual(get_default_cache_db_path(), ":memory:")

    def test_permission_failure_falls_back_to_memory(self):
        with mock.patch("pathlib.Path.mkdir", side_effect=PermissionError("Mock Permission Denied")):
            fallback_path = get_default_cache_db_path("custom_fail.db")
            self.assertEqual(fallback_path, ":memory:")


class TestAuditPoint4JSONSerializationSafety(unittest.TestCase):
    """Point 4: Serialization of pure JSON primitives and default=str resiliency."""

    def test_all_tools_return_pure_primitives(self):
        registry = ToolRegistry(cache_db_path=":memory:")
        res1 = registry.execute_tool("jevguard_prune_state", {"state": {"list": [1, 2], "float": 3.14}})
        self.assertIsInstance(res1, dict)
        json.dumps(res1)

        res2 = registry.execute_tool("jevguard_cache_fingerprint", {"state": {"k": "v"}})
        self.assertIsInstance(res2, dict)
        json.dumps(res2)

        res3 = registry.execute_tool("jevguard_calibrate", {"answers": {"q": {"type": "choice", "confidence": 0.5}}})
        self.assertIsInstance(res3, dict)
        json.dumps(res3)

    def test_server_serializes_non_serializable_objects_via_default_str(self):
        server = MCPServer(cache_db_path=":memory:")
        class NonSerializableObject:
            def __str__(self):
                return "<NonSerializableObjectInstance>"

        test_payload = {"key": NonSerializableObject(), "number": 123}
        with mock.patch.object(server.registry, "execute_tool", return_value=test_payload):
            call_msg = {
                "jsonrpc": "2.0",
                "id": 999,
                "method": "tools/call",
                "params": {"name": "jevguard_prune_state", "arguments": {"state": {}}},
            }
            resp = server.handle_message(call_msg)
            self.assertFalse(resp["result"]["isError"])
            content = json.loads(resp["result"]["content"][0]["text"])
            self.assertEqual(content["key"], "<NonSerializableObjectInstance>")


class TestAuditPoint5ConcurrencyAndStdioLifecycle(unittest.TestCase):
    """Point 5: Thread safety with RLock and graceful EOF / KeyboardInterrupt."""

    def test_concurrent_tool_execution_thread_safety(self):
        registry = ToolRegistry(cache_db_path=":memory:")
        errors = []

        def worker(thread_id):
            try:
                for i in range(25):
                    registry.execute_tool("jevguard_prune_state", {"state": {"thread": thread_id, "i": i}})
                    registry.execute_tool(
                        "jevguard_calibrate",
                        {"answers": {f"q_{i}": {"type": "choice", "confidence": 0.8, "probabilities": {"a": 0.8, "b": 0.2}}}}
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)

    def test_run_stdio_handles_eof_cleanly(self):
        server = MCPServer(cache_db_path=":memory:")
        input_stream = io.StringIO("")
        output_stream = io.StringIO()
        server.run_stdio(input_stream=input_stream, output_stream=output_stream)
        self.assertEqual(output_stream.getvalue(), "")

    def test_run_stdio_handles_keyboard_interrupt_cleanly(self):
        server = MCPServer(cache_db_path=":memory:")
        mock_stream = mock.MagicMock()
        mock_stream.readline.side_effect = KeyboardInterrupt()
        output_stream = io.StringIO()

        server.run_stdio(input_stream=mock_stream, output_stream=output_stream)
        self.assertFalse(server.running)


class TestAuditPoint6PyprojectToml(unittest.TestCase):
    """Point 6: Verification of zero dependencies and scripts entrypoint in pyproject.toml."""

    def test_pyproject_toml_configuration(self):
        pyproject_path = pathlib.Path(__file__).parent / "pyproject.toml"
        self.assertTrue(pyproject_path.exists())

        with open(pyproject_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("dependencies = []", content)
        self.assertIn("[project.scripts]", content)
        self.assertIn('jevguard-mcp = "jevguard_mcp.server:main"', content)


class TestAtomicToolsProtocol(unittest.TestCase):
    """Verifies the 3 high-level atomic tools through the MCP JSON-RPC protocol."""

    def setUp(self):
        self.server = MCPServer(cache_db_path=":memory:")

    def test_call_evaluate_command_safety_allow_autonomous(self):
        mock_answers = {
            "is_destructive": {
                "type": "noul",
                "noul": 0.05,
                "confidence": 0.95,
            },
            "risk_score": {
                "type": "score",
                "confidence": 0.90,
            },
            "execution_policy": {
                "type": "choice",
                "choice": "ALLOW_AUTONOMOUS",
                "confidence": 0.95,
                "probabilities": {
                    "ALLOW_AUTONOMOUS": 0.95,
                    "REQUIRE_HUMAN_APPROVAL": 0.04,
                    "DENY_DESTRUCTIVE": 0.01,
                },
            },
        }

        call_msg = {
            "jsonrpc": "2.0",
            "id": 201,
            "method": "tools/call",
            "params": {
                "name": "evaluate_command_safety",
                "arguments": {
                    "command": "pytest -v tests/",
                    "working_dir": "/workspace",
                    "elevated_privileges": False,
                    "mock_answers": mock_answers,
                },
            },
        }

        resp = self.server.handle_message(call_msg)
        self.assertIsNotNone(resp)
        self.assertFalse(resp.get("result", {}).get("isError", True))

        content = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(content["success"])
        self.assertEqual(content["policy"], "ALLOW_AUTONOMOUS")
        self.assertEqual(content["command"], "pytest -v tests/")
        self.assertFalse(content["verdict"]["requires_human"])
        self.assertIn("telemetry", content)
        self.assertIn("cache_fingerprint", content)

    def test_call_evaluate_command_safety_deny_destructive(self):
        mock_answers = {
            "is_destructive": {
                "type": "noul",
                "noul": 0.98,
                "confidence": 0.99,
            },
            "risk_score": {
                "type": "score",
                "confidence": 0.95,
            },
            "execution_policy": {
                "type": "choice",
                "choice": "DENY_DESTRUCTIVE",
                "confidence": 0.99,
                "probabilities": {
                    "DENY_DESTRUCTIVE": 0.99,
                    "REQUIRE_HUMAN_APPROVAL": 0.01,
                    "ALLOW_AUTONOMOUS": 0.0,
                },
            },
        }

        call_msg = {
            "jsonrpc": "2.0",
            "id": 202,
            "method": "tools/call",
            "params": {
                "name": "evaluate_command_safety",
                "arguments": {
                    "command": "rm -rf / --no-preserve-root",
                    "mock_answers": mock_answers,
                },
            },
        }

        resp = self.server.handle_message(call_msg)
        self.assertIsNotNone(resp)
        self.assertFalse(resp.get("result", {}).get("isError", True))

        content = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(content["success"])
        self.assertEqual(content["policy"], "DENY_DESTRUCTIVE")
        self.assertTrue(content["verdict"]["requires_human"])

    def test_call_evaluate_command_safety_elevated_privileges_requires_approval(self):
        mock_answers = {
            "is_destructive": {
                "type": "noul",
                "noul": 0.10,
                "confidence": 0.90,
            },
            "risk_score": {
                "type": "score",
                "confidence": 0.85,
            },
            "execution_policy": {
                "type": "choice",
                "choice": "ALLOW_AUTONOMOUS",
                "confidence": 0.85,
                "probabilities": {
                    "ALLOW_AUTONOMOUS": 0.85,
                    "REQUIRE_HUMAN_APPROVAL": 0.15,
                },
            },
        }

        call_msg = {
            "jsonrpc": "2.0",
            "id": 203,
            "method": "tools/call",
            "params": {
                "name": "evaluate_command_safety",
                "arguments": {
                    "command": "systemctl restart nginx",
                    "elevated_privileges": True,
                    "mock_answers": mock_answers,
                },
            },
        }

        resp = self.server.handle_message(call_msg)
        content = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(content["success"])
        self.assertEqual(content["policy"], "REQUIRE_HUMAN_APPROVAL")
        self.assertTrue(content["verdict"]["requires_human"])

    def test_call_evaluate_command_safety_missing_command_returns_structured_error(self):
        call_msg = {
            "jsonrpc": "2.0",
            "id": 204,
            "method": "tools/call",
            "params": {
                "name": "evaluate_command_safety",
                "arguments": {},
            },
        }

        resp = self.server.handle_message(call_msg)
        self.assertIsNotNone(resp)
        self.assertFalse(resp.get("result", {}).get("isError", True))

        content = json.loads(resp["result"]["content"][0]["text"])
        self.assertFalse(content["success"])
        self.assertEqual(content["error_type"], "ValueError")
        self.assertEqual(content["fallback_action"], "MANUAL_REVIEW_REQUIRED")

    def test_call_verify_code_patch_approve(self):
        patch = "--- a/utils.py\n+++ b/utils.py\n@@ -10,3 +10,3 @@\n-def add(a, b): return a - b\n+def add(a, b): return a + b\n"
        mock_answers = {
            "has_regression": {
                "type": "noul",
                "noul": 0.02,
                "confidence": 0.98,
            },
            "risk_score": {
                "type": "score",
                "confidence": 0.95,
            },
            "recommendation": {
                "type": "choice",
                "choice": "APPROVE",
                "confidence": 0.95,
                "probabilities": {"APPROVE": 0.95, "REQUEST_CHANGES": 0.05},
            },
        }

        call_msg = {
            "jsonrpc": "2.0",
            "id": 205,
            "method": "tools/call",
            "params": {
                "name": "verify_code_patch",
                "arguments": {
                    "patch_content": patch,
                    "target_file": "utils.py",
                    "risk_tolerance": "balanced",
                    "mock_answers": mock_answers,
                },
            },
        }

        resp = self.server.handle_message(call_msg)
        self.assertIsNotNone(resp)
        self.assertFalse(resp.get("result", {}).get("isError", True))

        content = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(content["success"])
        self.assertTrue(content["approved"])
        self.assertEqual(content["recommendation"], "APPROVE")
        self.assertEqual(content["risk_level"], "LOW")
        self.assertEqual(content["target_file"], "utils.py")

    def test_call_verify_code_patch_reject(self):
        patch = "--- a/db.py\n+++ b/db.py\n@@ -1 +1 @@\n-SELECT * FROM users;\n+DROP TABLE users;\n"
        mock_answers = {
            "has_regression": {
                "type": "noul",
                "noul": 0.95,
                "confidence": 0.99,
            },
            "risk_score": {
                "type": "score",
                "confidence": 0.99,
            },
            "recommendation": {
                "type": "choice",
                "choice": "REJECT",
                "confidence": 0.99,
                "probabilities": {"REJECT": 0.99, "APPROVE": 0.01},
            },
        }

        call_msg = {
            "jsonrpc": "2.0",
            "id": 206,
            "method": "tools/call",
            "params": {
                "name": "verify_code_patch",
                "arguments": {
                    "patch_content": patch,
                    "target_file": "db.py",
                    "mock_answers": mock_answers,
                },
            },
        }

        resp = self.server.handle_message(call_msg)
        content = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(content["success"])
        self.assertFalse(content["approved"])
        self.assertEqual(content["recommendation"], "REJECT")
        self.assertEqual(content["risk_level"], "CRITICAL")

    def test_call_verify_code_patch_strict_request_changes(self):
        patch = "--- a/auth.py\n+++ b/auth.py\n@@ -5 +5 @@\n-verify(token)\n+skip_verify(token)\n"
        mock_answers = {
            "has_regression": {
                "type": "noul",
                "noul": 0.25,
                "confidence": 0.80,
            },
            "risk_score": {
                "type": "score",
                "confidence": 0.70,
            },
            "recommendation": {
                "type": "choice",
                "choice": "APPROVE",
                "confidence": 0.60,
                "probabilities": {"APPROVE": 0.60, "REQUEST_CHANGES": 0.40},
            },
        }

        call_msg = {
            "jsonrpc": "2.0",
            "id": 207,
            "method": "tools/call",
            "params": {
                "name": "verify_code_patch",
                "arguments": {
                    "patch_content": patch,
                    "target_file": "auth.py",
                    "risk_tolerance": "strict",
                    "mock_answers": mock_answers,
                },
            },
        }

        resp = self.server.handle_message(call_msg)
        content = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(content["success"])
        self.assertFalse(content["approved"])
        self.assertEqual(content["recommendation"], "REQUEST_CHANGES")

    def test_call_verify_code_patch_missing_args_returns_structured_error(self):
        call_msg = {
            "jsonrpc": "2.0",
            "id": 208,
            "method": "tools/call",
            "params": {
                "name": "verify_code_patch",
                "arguments": {"target_file": "file.py"},
            },
        }

        resp = self.server.handle_message(call_msg)
        self.assertFalse(resp.get("result", {}).get("isError", True))
        content = json.loads(resp["result"]["content"][0]["text"])
        self.assertFalse(content["success"])
        self.assertEqual(content["error_type"], "ValueError")
        self.assertEqual(content["fallback_action"], "MANUAL_REVIEW_REQUIRED")

    def test_call_evaluate_decision_confident(self):
        mock_answers = {
            "decision": {
                "type": "choice",
                "choice": "PostgreSQL",
                "confidence": 0.94,
                "probabilities": {
                    "PostgreSQL": 0.94,
                    "SQLite": 0.04,
                    "DuckDB": 0.02,
                },
            }
        }

        call_msg = {
            "jsonrpc": "2.0",
            "id": 209,
            "method": "tools/call",
            "params": {
                "name": "evaluate_decision",
                "arguments": {
                    "context": "OLTP database handling multi-tenant e-commerce transactions",
                    "decision_question": "Which database engine should be used?",
                    "options": ["PostgreSQL", "SQLite", "DuckDB"],
                    "mock_answers": mock_answers,
                },
            },
        }

        resp = self.server.handle_message(call_msg)
        self.assertFalse(resp.get("result", {}).get("isError", True))

        content = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(content["success"])
        self.assertEqual(content["selected_option"], "PostgreSQL")
        self.assertEqual(content["confidence"], 0.94)
        self.assertEqual(content["status"], "CONFIDENT")
        self.assertFalse(content["is_escape_selected"])
        self.assertIn("options", content)

    def test_call_evaluate_decision_auto_injected_escape_selected(self):
        mock_answers = {
            "decision": {
                "type": "choice",
                "choice": ESCAPE_OPTION_KEY,
                "confidence": 0.98,
                "probabilities": {
                    ESCAPE_OPTION_KEY: 0.98,
                    "MySQL": 0.01,
                    "Redis": 0.01,
                },
            }
        }

        call_msg = {
            "jsonrpc": "2.0",
            "id": 210,
            "method": "tools/call",
            "params": {
                "name": "evaluate_decision",
                "arguments": {
                    "context": "We need an in-memory vector database with GPU acceleration",
                    "decision_question": "Choose the best candidate",
                    "options": ["MySQL", "Redis"],
                    "mock_answers": mock_answers,
                },
            },
        }

        resp = self.server.handle_message(call_msg)
        content = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(content["success"])
        self.assertEqual(content["selected_option"], ESCAPE_OPTION_KEY)
        self.assertTrue(content["is_escape_selected"])

    def test_call_evaluate_decision_empty_options_returns_structured_error(self):
        call_msg = {
            "jsonrpc": "2.0",
            "id": 211,
            "method": "tools/call",
            "params": {
                "name": "evaluate_decision",
                "arguments": {
                    "context": "Some context",
                    "decision_question": "Some question",
                    "options": [],
                },
            },
        }

        resp = self.server.handle_message(call_msg)
        self.assertFalse(resp.get("result", {}).get("isError", True))
        content = json.loads(resp["result"]["content"][0]["text"])
        self.assertFalse(content["success"])
        self.assertEqual(content["error_type"], "ValueError")
        self.assertEqual(content["fallback_action"], "MANUAL_REVIEW_REQUIRED")


class TestStructuredErrorHandlingAndProtocolStability(unittest.TestCase):
    """Verifies that failures never disconnect the MCP JSON-RPC protocol."""

    def setUp(self):
        self.server = MCPServer(cache_db_path=":memory:")

    def test_simulated_tool_exception_returns_structured_json(self):
        with mock.patch.object(self.server.registry, "_tool_evaluate", side_effect=RuntimeError("Simulated upstream gateway timeout")):
            call_msg = {
                "jsonrpc": "2.0",
                "id": 301,
                "method": "tools/call",
                "params": {
                    "name": "evaluate_command_safety",
                    "arguments": {"command": "git pull"},
                },
            }
            resp = self.server.handle_message(call_msg)
            self.assertIsNotNone(resp)
            self.assertFalse(resp.get("result", {}).get("isError", True))

            content = json.loads(resp["result"]["content"][0]["text"])
            self.assertFalse(content["success"])
            self.assertEqual(content["status"], "error")
            self.assertEqual(content["error_type"], "RuntimeError")
            self.assertEqual(content["message"], "Simulated upstream gateway timeout")
            self.assertEqual(content["verdict"], "MANUAL_REVIEW_REQUIRED")
            self.assertEqual(content["fallback_action"], "MANUAL_REVIEW_REQUIRED")

    def test_all_atomic_tools_without_api_key_return_structured_error(self):
        tools_to_test = [
            ("evaluate_command_safety", {"command": "npm run test"}),
            ("verify_code_patch", {"patch_content": "+line", "target_file": "a.txt"}),
            ("evaluate_decision", {"context": "ctx", "decision_question": "q", "options": ["A", "B"]}),
        ]

        for tool_name, args in tools_to_test:
            with self.subTest(tool=tool_name):
                call_msg = {
                    "jsonrpc": "2.0",
                    "id": 302,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": args},
                }
                resp = self.server.handle_message(call_msg)
                self.assertIsNotNone(resp)
                self.assertFalse(resp.get("result", {}).get("isError", True))
                content = json.loads(resp["result"]["content"][0]["text"])
                self.assertFalse(content["success"])
                self.assertEqual(content["status"], "error")
                self.assertEqual(content["error_type"], "ConfigurationError")
                self.assertEqual(content["verdict"], "MANUAL_REVIEW_REQUIRED")
                self.assertEqual(content["fallback_action"], "MANUAL_REVIEW_REQUIRED")


class TestHardenedSQLiteConcurrency(unittest.TestCase):
    """Verifies SQLite WAL mode, timeout, and transparent degradation to :memory:."""

    def test_sqlite_pragmas_configured_on_file_db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(pathlib.Path(tmpdir) / "test_concurrency.db")
            cache = DeterministicCache(db_path=db_path)

            with cache._get_connection() as conn:
                journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
                self.assertEqual(str(journal_mode).lower(), "wal")

                sync = conn.execute("PRAGMA synchronous;").fetchone()[0]
                self.assertEqual(int(sync), 1)

                busy_timeout = conn.execute("PRAGMA busy_timeout;").fetchone()[0]
                self.assertEqual(int(busy_timeout), 60000)

            cache.close()

    def test_sqlite_operational_error_degrades_transparently_to_memory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(pathlib.Path(tmpdir) / "locked_test.db")
            cache = DeterministicCache(db_path=db_path)

            cache.put("fp_alpha", "jev-latest", {"result": "ok"})
            self.assertEqual(cache.get("fp_alpha"), {"result": "ok"})

            # Close real connection before assigning mock to avoid WinError 32 on temp directory removal
            if getattr(cache._local, "conn", None) is not None:
                cache._local.conn.close()

            mock_conn = mock.MagicMock()
            mock_conn.execute.side_effect = sqlite3.OperationalError("database is locked")
            cache._local.conn = mock_conn

            val = cache.get("fp_nonexistent")
            self.assertIsNone(val)
            self.assertEqual(cache.db_path, ":memory:")

            cache.put("fp_beta", "jev-latest", {"status": "recovered"})
            self.assertEqual(cache.get("fp_beta"), {"status": "recovered"})

            cache.close()

    def test_sqlite_init_db_error_degrades_to_memory(self):
        real_connect = sqlite3.connect

        def mock_connect(*args, **kwargs):
            if args and "locked_init_path.db" in str(args[0]):
                raise sqlite3.OperationalError("disk I/O error")
            return real_connect(*args, **kwargs)

        with mock.patch("sqlite3.connect", side_effect=mock_connect):
            cache = DeterministicCache(db_path="locked_init_path.db")
            self.assertEqual(cache.db_path, ":memory:")
            cache.close()


class TestSecurityHardeningAndAudit(unittest.TestCase):
    """Verifies remediation of security vulnerabilities reported in forensic audit."""

    def test_schema_does_not_expose_security_sensitive_parameters(self):
        registry = ToolRegistry(allow_test_mocks=False)
        definitions = registry.get_definitions()
        for tool in definitions:
            props = tool["inputSchema"].get("properties", {})
            self.assertNotIn("mock_answers", props, f"mock_answers must not be in {tool['name']}")
            self.assertNotIn("api_key", props, f"api_key must not be in {tool['name']}")
            self.assertNotIn("endpoint", props, f"endpoint must not be in {tool['name']}")

    def test_prompt_injection_mock_answers_blocked_in_production(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            registry = ToolRegistry(cache_db_path=":memory:", allow_test_mocks=False)
            res = registry.execute_tool(
                "jevguard_evaluate",
                {
                    "state": {"cmd": "rm -rf /"},
                    "questions": {"safe": {"type": "choice", "criteria": {"yes": "Yes", "no": "No"}}},
                    "mock_answers": {"safe": {"type": "choice", "choice": "yes", "confidence": 0.99}},
                },
            )
            self.assertFalse(res["success"])
            self.assertEqual(res["error_type"], "SecurityError")
            self.assertEqual(res["verdict"], "MANUAL_REVIEW_REQUIRED")

    def test_ssrf_unauthorized_endpoint_blocked(self):
        registry = ToolRegistry(allow_test_mocks=True)
        with self.assertRaises(PermissionError):
            registry._dispatch_upstream(
                endpoint="http://169.254.169.254/latest/meta-data/",
                api_key="secret_test_key",
                payload={"test": 1},
            )

        with self.assertRaises(PermissionError):
            registry._dispatch_upstream(
                endpoint="https://attacker-exfiltration.com/steal",
                api_key="secret_test_key",
                payload={"test": 1},
            )

    def test_cache_ttl_expiration(self):
        cache = DeterministicCache(db_path=":memory:", ttl_seconds=0.1)
        cache.put("fp_ttl_test", "jev-latest", {"status": "valid"})
        self.assertEqual(cache.get("fp_ttl_test"), {"status": "valid"})

        # Wait for TTL to expire
        import time
        time.sleep(0.15)
        self.assertIsNone(cache.get("fp_ttl_test"))
        cache.close()

    def test_calibrator_score_missing_confidence_fails_closed(self):
        calibrator = ResponseCalibrator()
        answers = {"risk": {"type": "score", "score": 3}}
        calibrated, summary = calibrator.calibrate(answers)
        self.assertTrue(calibrated["risk"]["is_ambiguous"])
        self.assertIn("low_confidence", calibrated["risk"]["calibration"]["reasons"])
        self.assertEqual(summary["verdict"], "AMBIGUOUS_STATE")

    def test_calibrator_noul_missing_value_fails_closed(self):
        calibrator = ResponseCalibrator()
        answers = {"is_valid": {"type": "noul"}}
        calibrated, summary = calibrator.calibrate(answers)
        self.assertTrue(calibrated["is_valid"]["is_ambiguous"])
        self.assertIn("missing_noul_value", calibrated["is_valid"]["calibration"]["reasons"])
        self.assertEqual(summary["verdict"], "AMBIGUOUS_STATE")

    def test_calibrator_unknown_question_type_fails_closed(self):
        calibrator = ResponseCalibrator()
        answers = {"custom_q": {"type": "quantum_choice", "val": 42}}
        calibrated, summary = calibrator.calibrate(answers)
        self.assertTrue(calibrated["custom_q"]["is_ambiguous"])
        self.assertIn("unknown_question_type", calibrated["custom_q"]["calibration"]["reasons"])
        self.assertEqual(summary["verdict"], "AMBIGUOUS_STATE")

    def test_cache_volatile_keys_does_not_strip_domain_time(self):
        fp1 = DeterministicCache.compute_fingerprint(
            model="jev-latest",
            state={"action": "schedule", "time": "10:00"},
        )
        fp2 = DeterministicCache.compute_fingerprint(
            model="jev-latest",
            state={"action": "schedule", "time": "14:00"},
        )
        self.assertNotEqual(fp1, fp2, "Domain time field must not be stripped or cause collision")

    def test_cache_ignore_keys_unions_with_defaults(self):
        # State with both custom ignored key and default volatile timestamp
        state1 = {"user": "bob", "tenant_id": "tenant_1", "timestamp": 1000}
        state2 = {"user": "bob", "tenant_id": "tenant_2", "timestamp": 2000}

        fp1 = DeterministicCache.compute_fingerprint(
            model="jev-latest",
            state=state1,
            ignore_keys=["tenant_id"],
        )
        fp2 = DeterministicCache.compute_fingerprint(
            model="jev-latest",
            state=state2,
            ignore_keys=["tenant_id"],
        )
        self.assertEqual(fp1, fp2, "Both custom key tenant_id and default timestamp must be ignored")


if __name__ == "__main__":
    unittest.main(verbosity=2)
