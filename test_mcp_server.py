"""
test_mcp_server.py - Comprehensive Unit and Stdio Test Suite for JevGuard MCP Server.
Implements 100% Python standard library (unittest, io, json, tempfile, os).
Strictly adheres to Humanizer English standards.
"""

import io
import json
import math
import os
import tempfile
import unittest

from jevguard_mcp.server import MCPServer
from jevguard_mcp.tools import (
    DeterministicCache,
    ESCAPE_OPTION_KEY,
    QuestionOptimizer,
    ResponseCalibrator,
    StatePruner,
    ToolRegistry,
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
        self.assertEqual(len(tools), 4)

        tool_names = {t["name"] for t in tools}
        expected_names = {
            "jevguard_evaluate",
            "jevguard_calibrate",
            "jevguard_prune_state",
            "jevguard_cache_fingerprint",
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
        text = "  multiple   spaces   and \n\t tabs  "
        pruned = StatePruner.prune(text)
        self.assertEqual(pruned, "multiple spaces and tabs")

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

if __name__ == "__main__":
    unittest.main(verbosity=2)
