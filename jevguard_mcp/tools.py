"""
JevGuard MCP Tools - Tool registration and execution engine.
Implements state pruning, closed-world escape injection, certainty calibration,
canonical SHA-256 fingerprinting, and deterministic evaluation.
All operations rely solely on the Python standard library.
"""

import contextlib
import hashlib
import json
import logging
import math
import os
import random
import socket
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

logger = logging.getLogger("jevguard.mcp.tools")

ESCAPE_OPTION_KEY: str = "UNRESOLVED_OR_OTHER"
ESCAPE_OPTION_DESC: str = "State does not match defined criteria"

ESCAPE_CANDIDATE_KEYS: Set[str] = {
    "unresolved_or_other",
    "other",
    "unknown",
    "unresolved",
    "not_applicable",
    "n/a",
    "neither",
    "no_match",
    "none_of_the_above",
    "none_of_above",
    "unhandled",
    "misc",
}

DEFAULT_VOLATILE_KEYS: Set[str] = {
    "timestamp",
    "time",
    "created_at",
    "updated_at",
    "trace_id",
    "span_id",
    "request_id",
    "correlation_id",
    "nonce",
    "createdat",
    "updatedat",
    "traceid",
    "requestid",
    "x_trace_id",
    "x_request_id",
    "x_correlation_id",
    "xtraceid",
    "xrequestid",
}


class StatePruner:
    """Removes empty values, nulls, and duplicate whitespace while preventing cycles."""

    @classmethod
    def prune(
        cls,
        data: Any,
        prune_lists: bool = False,
        seen: Optional[Set[int]] = None,
    ) -> Any:
        if seen is None:
            seen = set()

        if isinstance(data, (dict, list, tuple, set, frozenset)):
            obj_id = id(data)
            if obj_id in seen:
                return "<cyclic_ref>"
            seen.add(obj_id)
        else:
            obj_id = None

        try:
            if isinstance(data, dict):
                pruned: Dict[str, Any] = {}
                for key, value in data.items():
                    if value is None:
                        continue
                    str_key = str(key)
                    pruned_value = cls.prune(value, prune_lists=prune_lists, seen=seen)
                    if pruned_value is None:
                        continue
                    if isinstance(pruned_value, (str, dict, list, tuple, set, frozenset)) and len(pruned_value) == 0:
                        continue
                    pruned[str_key] = pruned_value
                return pruned

            elif isinstance(data, list):
                if prune_lists:
                    pruned_list: List[Any] = []
                    for item in data:
                        if item is None:
                            continue
                        pruned_item = cls.prune(item, prune_lists=prune_lists, seen=seen)
                        if pruned_item is None:
                            continue
                        if isinstance(pruned_item, (str, dict)) and len(pruned_item) == 0:
                            continue
                        pruned_list.append(pruned_item)
                    return pruned_list
                else:
                    return [cls.prune(item, prune_lists=prune_lists, seen=seen) for item in data]

            elif isinstance(data, tuple):
                return tuple(cls.prune(item, prune_lists=prune_lists, seen=seen) for item in data)

            elif isinstance(data, (set, frozenset)):
                pruned_items = [cls.prune(item, prune_lists=prune_lists, seen=seen) for item in data]
                try:
                    return sorted(pruned_items)
                except TypeError:
                    return sorted(pruned_items, key=lambda x: str(x))

            elif isinstance(data, float):
                if math.isnan(data) or math.isinf(data):
                    return None
                return data

            elif isinstance(data, str):
                return " ".join(data.strip().split())

            return data
        finally:
            if obj_id is not None:
                seen.remove(obj_id)

    @classmethod
    def estimate_tokens(cls, data: Any) -> int:
        if isinstance(data, str):
            return max(1, len(data) // 4)
        raw = json.dumps(data, separators=(",", ":"))
        return max(1, len(raw) // 4)


class DeterministicCache:
    """Provides instant 0-token response retrieval for repeated queries."""

    def __init__(
        self,
        db_path: str = ":memory:",
        max_memory_items: int = 500,
        default_ignore_keys: Optional[Iterable[str]] = None,
    ):
        self.db_path = db_path
        self.max_memory_items = max_memory_items
        self.default_ignore_keys = (
            {str(k).strip().lower().replace("-", "_") for k in default_ignore_keys}
            if default_ignore_keys is not None
            else DEFAULT_VOLATILE_KEYS
        )
        self._memory_lru: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._local = threading.local()
        self._shared_conn: Optional[sqlite3.Connection] = None

        if self.db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row

        self.stats = {
            "hits": 0,
            "misses": 0,
            "tokens_saved": 0,
        }
        self._init_db()

    @contextlib.contextmanager
    def _get_connection(self):
        if self._shared_conn is not None:
            with self._lock:
                yield self._shared_conn
        else:
            conn = getattr(self._local, "conn", None)
            if conn is None:
                conn = sqlite3.connect(self.db_path, timeout=20.0)
                conn.row_factory = sqlite3.Row
                try:
                    conn.execute("PRAGMA journal_mode=WAL")
                    conn.execute("PRAGMA synchronous=NORMAL")
                except Exception as err:
                    logger.debug("PRAGMA setup note: %s", err)
                self._local.conn = conn
            with self._lock:
                yield conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evaluation_cache (
                    fingerprint TEXT PRIMARY KEY,
                    model TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    hit_count INTEGER DEFAULT 0,
                    tokens_estimate INTEGER DEFAULT 0
                )
                """
            )
            conn.commit()

    @classmethod
    def _strip_volatile_keys(
        cls,
        data: Any,
        ignore_keys: Set[str],
        seen: Optional[Set[int]] = None,
    ) -> Any:
        if seen is None:
            seen = set()

        if isinstance(data, (dict, list, tuple, set, frozenset)):
            obj_id = id(data)
            if obj_id in seen:
                return "<cyclic_ref>"
            seen.add(obj_id)
        else:
            obj_id = None

        try:
            if isinstance(data, dict):
                cleaned: Dict[str, Any] = {}
                for key, value in data.items():
                    norm_key = str(key).strip().lower().replace("-", "_")
                    if norm_key in ignore_keys:
                        continue
                    cleaned[str(key)] = cls._strip_volatile_keys(value, ignore_keys, seen=seen)
                return cleaned
            elif isinstance(data, list):
                return [cls._strip_volatile_keys(item, ignore_keys, seen=seen) for item in data]
            elif isinstance(data, tuple):
                return tuple(cls._strip_volatile_keys(item, ignore_keys, seen=seen) for item in data)
            elif isinstance(data, (set, frozenset)):
                items = [cls._strip_volatile_keys(item, ignore_keys, seen=seen) for item in data]
                try:
                    return sorted(items)
                except TypeError:
                    return sorted(items, key=lambda x: str(x))
            return data
        finally:
            if obj_id is not None:
                seen.remove(obj_id)

    @classmethod
    def compute_fingerprint(
        cls,
        model: str = "jev-latest",
        state: Any = None,
        wire_questions: Optional[Dict[str, Any]] = None,
        ignore_keys: Optional[Iterable[str]] = None,
    ) -> str:
        if isinstance(model, (dict, list)):
            if wire_questions is not None and not isinstance(wire_questions, dict):
                ignore_keys = wire_questions
            wire_questions = state if isinstance(state, dict) else {}
            state = model
            model = "jev-latest"

        target_model = model or "jev-latest"
        target_state = state if state is not None else {}
        target_questions = wire_questions if wire_questions is not None else {}

        keys_to_ignore = (
            {str(k).strip().lower().replace("-", "_") for k in ignore_keys}
            if ignore_keys is not None
            else DEFAULT_VOLATILE_KEYS
        )
        filtered_state = (
            cls._strip_volatile_keys(target_state, keys_to_ignore)
            if keys_to_ignore
            else target_state
        )

        canonical_struct = {
            "model": str(target_model).strip().lower(),
            "questions": target_questions,
            "state": filtered_state,
        }
        canonical_bytes = json.dumps(
            canonical_struct,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    def get(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            if fingerprint in self._memory_lru:
                self.stats["hits"] += 1
                item = self._memory_lru[fingerprint]
                self.stats["tokens_saved"] += item.get("tokens_estimate", 0)
                item["hit_count"] = item.get("hit_count", 0) + 1
                return item["data"]

        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "SELECT response_json, tokens_estimate FROM evaluation_cache WHERE fingerprint = ?",
                    (fingerprint,),
                )
                row = cur.fetchone()
                if row:
                    with self._lock:
                        self.stats["hits"] += 1
                        data = json.loads(row["response_json"])
                        tokens = row["tokens_estimate"]
                        self.stats["tokens_saved"] += tokens
                        self._promote_lru(fingerprint, data, tokens)
                    return data
        except Exception as err:
            logger.warning("Cache lookup error for %s: %s", fingerprint, err)

        with self._lock:
            self.stats["misses"] += 1
        return None

    def put(
        self,
        fingerprint: str,
        model: str,
        response_data: Dict[str, Any],
        input_tokens_estimate: int = 0,
    ) -> None:
        try:
            raw_json = json.dumps(response_data, separators=(",", ":"))
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO evaluation_cache (
                        fingerprint, model, response_json, created_at, hit_count, tokens_estimate
                    ) VALUES (?, ?, ?, ?, COALESCE((SELECT hit_count FROM evaluation_cache WHERE fingerprint = ?), 0), ?)
                    """,
                    (
                        fingerprint,
                        model,
                        raw_json,
                        time.time(),
                        fingerprint,
                        input_tokens_estimate,
                    ),
                )
                conn.commit()

            with self._lock:
                self._promote_lru(fingerprint, response_data, input_tokens_estimate)
        except Exception as err:
            logger.warning("Cache write error for %s: %s", fingerprint, err)

    def _promote_lru(
        self,
        fingerprint: str,
        data: Dict[str, Any],
        tokens_estimate: int,
    ) -> None:
        if len(self._memory_lru) >= self.max_memory_items:
            oldest_key = next(iter(self._memory_lru))
            del self._memory_lru[oldest_key]
        self._memory_lru[fingerprint] = {
            "data": data,
            "hit_count": 0,
            "tokens_estimate": tokens_estimate,
        }

    def clear(self) -> None:
        with self._lock:
            self._memory_lru.clear()
            self.stats["hits"] = 0
            self.stats["misses"] = 0
            self.stats["tokens_saved"] = 0
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM evaluation_cache")
                conn.commit()
        except Exception as err:
            logger.warning("Cache clear error: %s", err)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self.stats["hits"] + self.stats["misses"]
            rate = round((self.stats["hits"] / total) * 100, 2) if total > 0 else 0.0
            return {
                "hit_rate_pct": rate,
                "hits": self.stats["hits"],
                "misses": self.stats["misses"],
                "tokens_saved": self.stats["tokens_saved"],
            }

    def close(self) -> None:
        with self._lock:
            if self._shared_conn is not None:
                try:
                    self._shared_conn.close()
                except Exception:
                    pass
                self._shared_conn = None
            conn = getattr(self._local, "conn", None)
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
                self._local.conn = None


class ResponseCalibrator:
    """Evaluates probability spread on decisions to detect ambiguity and flat distributions."""

    MIN_TOP_PROBABILITY: float = 0.40
    MIN_DISPERSION_GAP: float = 0.15
    DEFAULT_NOUL_UNCERTAINTY_MARGIN: float = 0.12

    def __init__(
        self,
        min_top_prob: float = MIN_TOP_PROBABILITY,
        min_dispersion_gap: float = MIN_DISPERSION_GAP,
        noul_uncertainty_margin: float = DEFAULT_NOUL_UNCERTAINTY_MARGIN,
    ):
        self.min_top_prob = min_top_prob
        self.min_dispersion_gap = min_dispersion_gap
        self.noul_margin = noul_uncertainty_margin

    def calibrate(self, raw_answers: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        calibrated: Dict[str, Any] = {}
        ambiguous_questions: List[str] = []

        for name, ans in raw_answers.items():
            if not isinstance(ans, dict):
                calibrated[name] = ans
                continue

            item = dict(ans)
            q_type = str(item.get("type", "")).strip().lower()

            if q_type == "choice":
                self._calibrate_choice(item)
            elif q_type == "score":
                self._calibrate_score(item)
            elif q_type == "noul":
                self._calibrate_noul(item)

            if item.get("is_ambiguous", False):
                ambiguous_questions.append(name)

            calibrated[name] = item

        summary = {
            "ambiguous_count": len(ambiguous_questions),
            "ambiguous_questions": ambiguous_questions,
            "has_ambiguity": len(ambiguous_questions) > 0,
            "total_evaluated": len(calibrated),
            "verdict": "AMBIGUOUS_STATE" if ambiguous_questions else "CONFIDENT",
        }

        return calibrated, summary

    def _calibrate_choice(self, item: Dict[str, Any]) -> None:
        probs = item.get("probabilities", {})
        parsed_pairs: List[Tuple[str, float]] = []
        if isinstance(probs, dict):
            for k, v in probs.items():
                try:
                    parsed_pairs.append((str(k), float(v)))
                except (ValueError, TypeError):
                    pass

        if not parsed_pairs:
            try:
                conf = float(item.get("confidence", 0.0))
            except (ValueError, TypeError):
                conf = 0.0
            is_amb = conf < self.min_top_prob
            item["is_ambiguous"] = is_amb
            item["status"] = "AMBIGUOUS_STATE" if is_amb else "CONFIDENT"
            item["calibration"] = {
                "dispersion_gap": conf,
                "reasons": ["low_confidence"] if is_amb else [],
                "runner_up_choice": None,
                "runner_up_probability": 0.0,
                "top_choice": item.get("choice"),
                "top_probability": conf,
            }
            return

        sorted_pairs = sorted(parsed_pairs, key=lambda x: x[1], reverse=True)
        top_k, top_p = sorted_pairs[0]
        runner_k, runner_p = sorted_pairs[1] if len(sorted_pairs) > 1 else (None, 0.0)
        gap = top_p - runner_p

        reasons: List[str] = []
        if top_p < self.min_top_prob:
            reasons.append("low_confidence")
        if len(sorted_pairs) > 1 and gap < self.min_dispersion_gap:
            reasons.append("flat_distribution")

        is_amb = len(reasons) > 0
        item["is_ambiguous"] = is_amb
        item["status"] = "AMBIGUOUS_STATE" if is_amb else "CONFIDENT"
        item["calibration"] = {
            "dispersion_gap": round(gap, 4),
            "reasons": reasons,
            "runner_up_choice": runner_k,
            "runner_up_probability": round(runner_p, 4),
            "top_choice": top_k,
            "top_probability": round(top_p, 4),
        }

    def _calibrate_score(self, item: Dict[str, Any]) -> None:
        try:
            conf = float(item.get("confidence", 1.0))
        except (ValueError, TypeError):
            conf = 0.0

        probs = item.get("probabilities", {})
        reasons: List[str] = []

        if conf < self.min_top_prob:
            reasons.append("low_confidence")

        dispersion_gap = conf
        if isinstance(probs, dict) and len(probs) >= 2:
            parsed_probs: List[float] = []
            for v in probs.values():
                try:
                    parsed_probs.append(float(v))
                except (ValueError, TypeError):
                    pass
            if len(parsed_probs) >= 2:
                sorted_probs = sorted(parsed_probs, reverse=True)
                top_p = sorted_probs[0]
                runner_p = sorted_probs[1]
                dispersion_gap = top_p - runner_p
                if top_p < self.min_top_prob and "low_confidence" not in reasons:
                    reasons.append("low_confidence")
                if dispersion_gap < self.min_dispersion_gap:
                    reasons.append("flat_distribution")

        is_amb = len(reasons) > 0
        item["is_ambiguous"] = is_amb
        item["status"] = "AMBIGUOUS_STATE" if is_amb else "CONFIDENT"
        item["calibration"] = {
            "confidence": round(conf, 4),
            "dispersion_gap": round(dispersion_gap, 4),
            "reasons": reasons,
        }

    def _calibrate_noul(self, item: Dict[str, Any]) -> None:
        val = item.get("noul")
        if val is None:
            return
        try:
            prob = float(val)
        except (ValueError, TypeError):
            return

        dist = abs(prob - 0.50)
        is_amb = dist < self.noul_margin

        item["is_ambiguous"] = is_amb
        item["status"] = "AMBIGUOUS_STATE" if is_amb else "CONFIDENT"
        item["calibration"] = {
            "boundary_distance": round(dist, 4),
            "probability": round(prob, 4),
            "reasons": ["boundary_uncertainty"] if is_amb else [],
        }


class QuestionOptimizer:
    """Normalizes questions and injects closed-world escape options."""

    def __init__(self, default_model: str = "jev-latest", auto_inject_escapes: bool = True):
        self.default_model = default_model
        self.auto_inject_escapes = auto_inject_escapes

    def normalize_questions(
        self,
        questions: Union[Dict[str, Any], List[Dict[str, Any]]],
        auto_inject_escapes: bool = True,
    ) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
        if not questions:
            raise ValueError("Questions payload cannot be empty.")

        wire_questions: Dict[str, Dict[str, Any]] = {}
        injected_escapes: Dict[str, str] = {}

        if isinstance(questions, dict):
            for name, q in questions.items():
                wire_q, injected = self._process_question(name, q, auto_inject_escapes=auto_inject_escapes)
                wire_questions[name] = wire_q
                if injected:
                    injected_escapes[name] = ESCAPE_OPTION_KEY
        elif isinstance(questions, list):
            for idx, q in enumerate(questions):
                if not isinstance(q, dict):
                    raise ValueError(f"Question at index {idx} must be a dictionary.")
                name = str(q.get("name") or f"q_{idx + 1}").strip()
                wire_q, injected = self._process_question(name, q, auto_inject_escapes=auto_inject_escapes)
                wire_questions[name] = wire_q
                if injected:
                    injected_escapes[name] = ESCAPE_OPTION_KEY
        else:
            raise ValueError(f"Questions must be a dictionary or list, got {type(questions).__name__}")

        return wire_questions, injected_escapes

    def _process_question(
        self,
        name: str,
        q: Any,
        auto_inject_escapes: bool = True,
    ) -> Tuple[Dict[str, Any], bool]:
        if not isinstance(q, dict):
            raise ValueError(f"Invalid question definition for '{name}': {q}")

        q_type = str(q.get("type", "noul")).strip().lower()
        instructions = str(q.get("instructions") or q.get("question") or "")

        allow_escape = True
        wire_dict: Dict[str, Any] = {}

        if q_type == "noul":
            wire_dict = {
                "type": "noul",
                "instructions": instructions,
            }
            if "criteria" in q and q["criteria"] is not None:
                wire_dict["criteria"] = q["criteria"]

        elif q_type == "score":
            criteria = q.get("criteria", [])
            if not isinstance(criteria, list):
                criteria = [criteria]
            wire_dict = {
                "type": "score",
                "instructions": instructions,
                "criteria": criteria,
            }

        elif q_type == "choice":
            raw_crit = q.get("criteria") if q.get("criteria") is not None else q.get("options", {})
            if isinstance(raw_crit, list):
                raw_crit = {str(item): str(item) for item in raw_crit}
            elif not isinstance(raw_crit, dict):
                raw_crit = {}
            criteria = {str(k): str(v) for k, v in raw_crit.items()}
            closed = bool(q.get("closed_world", False))
            allow_escape = q.get("auto_inject_escape", not closed)
            wire_dict = {
                "type": "choice",
                "instructions": instructions,
                "criteria": criteria,
                "closed_world": closed,
            }
        else:
            raise ValueError(f"Unsupported question type '{q_type}' in '{name}'")

        injected_escape = False
        if wire_dict["type"] == "choice" and auto_inject_escapes and allow_escape:
            curr_criteria = dict(wire_dict["criteria"])
            has_escape = any(k.strip().lower() in ESCAPE_CANDIDATE_KEYS for k in curr_criteria.keys())
            if not has_escape:
                curr_criteria[ESCAPE_OPTION_KEY] = ESCAPE_OPTION_DESC
                injected_escape = True
            wire_dict["criteria"] = curr_criteria

        return wire_dict, injected_escape

    def optimize_and_wire(
        self,
        state: Any,
        questions: Union[Dict[str, Any], List[Dict[str, Any]]],
        model: Optional[str] = None,
        auto_inject_escapes: Optional[bool] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        target_model = (model or self.default_model).strip() or self.default_model
        pruned_state = StatePruner.prune(state)

        should_inject = (
            self.auto_inject_escapes if auto_inject_escapes is None else auto_inject_escapes
        )
        wire_questions, injected_escapes = self.normalize_questions(
            questions, auto_inject_escapes=should_inject
        )

        wire_payload = {
            "model": target_model,
            "questions": wire_questions,
            "state": pruned_state,
        }

        metadata = {
            "auto_inject_escapes_enabled": should_inject,
            "estimated_tokens": StatePruner.estimate_tokens(wire_payload),
            "has_injected_escapes": len(injected_escapes) > 0,
            "injected_escapes": injected_escapes,
            "model": target_model,
            "total_questions": len(wire_questions),
        }

        return wire_payload, metadata


class ToolRegistry:
    """Registry maintaining tool schemas and operational handlers."""

    def __init__(self, cache_db_path: str = ":memory:"):
        self.cache = DeterministicCache(db_path=cache_db_path)
        self.optimizer = QuestionOptimizer()
        self.calibrator = ResponseCalibrator()

    def get_definitions(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "jevguard_evaluate",
                "description": (
                    "Executes the deterministic JevGuard evaluation pipeline including state pruning, "
                    "closed-world escape injection, certainty calibration, and 0-token caching."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "state": {
                            "description": "Input state payload to evaluate against criteria."
                        },
                        "questions": {
                            "description": "Dictionary or list of question definitions (noul, score, choice).",
                            "oneOf": [{"type": "object"}, {"type": "array"}],
                        },
                        "model": {
                            "type": "string",
                            "description": "Target model identifier (default: jev-latest).",
                            "default": "jev-latest",
                        },
                        "auto_inject_escapes": {
                            "type": "boolean",
                            "description": "Automatically inject neutral escape alternatives into categorical choices.",
                            "default": True,
                        },
                        "bypass_cache": {
                            "type": "boolean",
                            "description": "Bypass deterministic cache lookup.",
                            "default": False,
                        },
                        "api_key": {
                            "type": "string",
                            "description": "Optional TypeSafe AI API key (defaults to TYPESAFE_API_KEY environment variable).",
                        },
                        "endpoint": {
                            "type": "string",
                            "description": "Upstream API endpoint (default: https://api.typesafe.ai/v1/systemone).",
                            "default": "https://api.typesafe.ai/v1/systemone",
                        },
                        "timeout": {
                            "type": "number",
                            "description": "HTTP request timeout in seconds (default: 30.0).",
                            "default": 30.0,
                        },
                        "mock_answers": {
                            "type": "object",
                            "description": "Optional raw answers dictionary for testing or offline execution.",
                        },
                    },
                    "required": ["state", "questions"],
                },
            },
            {
                "name": "jevguard_calibrate",
                "description": (
                    "Evaluates probability distributions across answers to identify ambiguity, "
                    "low confidence (top_prob < 0.40), and flat distributions (dispersion_gap < 0.15)."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "answers": {
                            "type": "object",
                            "description": "Dictionary mapping question names to answers with probabilities or confidence values.",
                        },
                        "min_top_prob": {
                            "type": "number",
                            "description": "Minimum confidence threshold for top choice (default: 0.40).",
                            "default": 0.40,
                        },
                        "min_dispersion_gap": {
                            "type": "number",
                            "description": "Minimum probability gap between top choice and runner up (default: 0.15).",
                            "default": 0.15,
                        },
                        "noul_uncertainty_margin": {
                            "type": "number",
                            "description": "Uncertainty margin around 0.50 boundary for noul probabilities (default: 0.12).",
                            "default": 0.12,
                        },
                    },
                    "required": ["answers"],
                },
            },
            {
                "name": "jevguard_prune_state",
                "description": (
                    "Sanitizes and prunes complex JSON state payloads by removing nulls, empty collections, "
                    "collapsing whitespace, and protecting against cyclic references."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "state": {
                            "description": "The state payload (dict, list, or primitive) to sanitize and prune."
                        },
                        "prune_lists": {
                            "type": "boolean",
                            "description": "Whether to strip empty values and nulls from lists (default: false).",
                            "default": False,
                        },
                    },
                    "required": ["state"],
                },
            },
            {
                "name": "jevguard_cache_fingerprint",
                "description": (
                    "Calculates a canonical SHA-256 fingerprint from state and questions with volatile "
                    "key masking (timestamp, trace_id, request_id) for 0-token deterministic caching."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "state": {
                            "description": "State payload to include in fingerprint computation."
                        },
                        "questions": {
                            "description": "Question definitions dictionary or list.",
                            "oneOf": [{"type": "object"}, {"type": "array"}],
                        },
                        "model": {
                            "type": "string",
                            "description": "Target model identifier (default: jev-latest).",
                            "default": "jev-latest",
                        },
                        "ignore_keys": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of volatile keys to mask in addition to standard defaults.",
                        },
                    },
                    "required": ["state"],
                },
            },
        ]

    def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(arguments, dict):
            raise ValueError(f"Tool arguments must be a dictionary, got {type(arguments).__name__}")

        if name == "jevguard_prune_state":
            return self._tool_prune_state(arguments)
        elif name == "jevguard_cache_fingerprint":
            return self._tool_cache_fingerprint(arguments)
        elif name == "jevguard_calibrate":
            return self._tool_calibrate(arguments)
        elif name == "jevguard_evaluate":
            return self._tool_evaluate(arguments)
        else:
            raise KeyError(f"Unknown tool: '{name}'")

    def _tool_prune_state(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if "state" not in arguments:
            raise ValueError("Missing required argument: 'state'")
        state = arguments["state"]
        prune_lists = bool(arguments.get("prune_lists", False))

        pruned = StatePruner.prune(state, prune_lists=prune_lists)
        tokens_estimate = StatePruner.estimate_tokens(pruned)
        return {
            "estimated_tokens": tokens_estimate,
            "pruned_state": pruned,
        }

    def _tool_cache_fingerprint(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if "state" not in arguments:
            raise ValueError("Missing required argument: 'state'")
        state = arguments["state"]
        questions = arguments.get("questions") or {}
        model = str(arguments.get("model", "jev-latest")).strip() or "jev-latest"
        ignore_keys = arguments.get("ignore_keys")

        wire_questions = questions
        if isinstance(questions, (dict, list)) and questions:
            try:
                wire_questions, _ = self.optimizer.normalize_questions(questions, auto_inject_escapes=False)
            except Exception:
                wire_questions = questions

        fp = DeterministicCache.compute_fingerprint(
            model=model,
            state=state,
            wire_questions=wire_questions if isinstance(wire_questions, dict) else {},
            ignore_keys=ignore_keys,
        )

        keys_used = sorted(
            list(
                {str(k).strip().lower().replace("-", "_") for k in ignore_keys}
                if ignore_keys is not None
                else DEFAULT_VOLATILE_KEYS
            )
        )

        return {
            "fingerprint": fp,
            "masked_volatile_keys": keys_used,
            "model": model,
        }

    def _tool_calibrate(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if "answers" not in arguments:
            raise ValueError("Missing required argument: 'answers'")
        raw_answers = arguments["answers"]
        if not isinstance(raw_answers, dict):
            raise ValueError("Argument 'answers' must be a dictionary mapping question names to answers")

        min_top_prob = float(arguments.get("min_top_prob", ResponseCalibrator.MIN_TOP_PROBABILITY))
        min_dispersion_gap = float(arguments.get("min_dispersion_gap", ResponseCalibrator.MIN_DISPERSION_GAP))
        noul_margin = float(arguments.get("noul_uncertainty_margin", ResponseCalibrator.DEFAULT_NOUL_UNCERTAINTY_MARGIN))

        calibrator = ResponseCalibrator(
            min_top_prob=min_top_prob,
            min_dispersion_gap=min_dispersion_gap,
            noul_uncertainty_margin=noul_margin,
        )
        calibrated_answers, summary = calibrator.calibrate(raw_answers)

        return {
            "calibrated_answers": calibrated_answers,
            "summary": summary,
        }

    def _tool_evaluate(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if "state" not in arguments:
            raise ValueError("Missing required argument: 'state'")
        if "questions" not in arguments:
            raise ValueError("Missing required argument: 'questions'")

        state = arguments["state"]
        questions = arguments["questions"]
        model = str(arguments.get("model", "jev-latest")).strip() or "jev-latest"
        auto_inject = bool(arguments.get("auto_inject_escapes", True))
        bypass_cache = bool(arguments.get("bypass_cache", False))
        api_key = str(arguments.get("api_key") or os.environ.get("TYPESAFE_API_KEY", "")).strip()
        endpoint = str(arguments.get("endpoint", "https://api.typesafe.ai/v1/systemone")).strip()
        timeout = float(arguments.get("timeout", 30.0))
        mock_answers = arguments.get("mock_answers")

        t0 = time.perf_counter()

        wire_payload, opt_metadata = self.optimizer.optimize_and_wire(
            state=state,
            questions=questions,
            model=model,
            auto_inject_escapes=auto_inject,
        )
        tokens_estimate = opt_metadata["estimated_tokens"]

        fingerprint = DeterministicCache.compute_fingerprint(
            model=wire_payload["model"],
            state=wire_payload["state"],
            wire_questions=wire_payload["questions"],
        )

        if not bypass_cache:
            cached_data = self.cache.get(fingerprint)
            if cached_data is not None:
                t1 = time.perf_counter()
                latency_ms = round((t1 - t0) * 1000, 3)
                return {
                    "answers": cached_data["answers"],
                    "cache_fingerprint": fingerprint,
                    "cached": True,
                    "calibration": cached_data["calibration"],
                    "optimization": opt_metadata,
                    "success": True,
                    "telemetry": {
                        "latency_calibration_ms": 0.0,
                        "latency_inference_ms": 0.0,
                        "latency_total_ms": latency_ms,
                        "mode": "deterministic_cache_hit",
                        "tokens_consumed": 0,
                        "tokens_saved": tokens_estimate,
                    },
                }

        raw_answers: Dict[str, Any] = {}
        inference_latency_ms = 0.0

        if mock_answers is not None:
            if not isinstance(mock_answers, dict):
                raise ValueError("Argument 'mock_answers' must be a dictionary")
            raw_answers = mock_answers
        elif api_key:
            dispatch_res = self._dispatch_upstream(
                endpoint=endpoint,
                api_key=api_key,
                payload=wire_payload,
                timeout=timeout,
            )
            inference_latency_ms = dispatch_res.get("latency_ms", 0.0)
            raw_answers = dispatch_res.get("data", {}).get("answers", {})
        else:
            return {
                "cache_fingerprint": fingerprint,
                "cached": False,
                "notice": "Offline mode: set TYPESAFE_API_KEY or provide mock_answers to execute inference.",
                "optimization": opt_metadata,
                "success": True,
                "wire_payload": wire_payload,
            }

        t_cal0 = time.perf_counter()
        calibrated_answers, calib_summary = self.calibrator.calibrate(raw_answers)
        t_cal1 = time.perf_counter()
        calib_ms = round((t_cal1 - t_cal0) * 1000, 3)

        self.cache.put(
            fingerprint=fingerprint,
            model=wire_payload["model"],
            response_data={
                "answers": calibrated_answers,
                "calibration": calib_summary,
            },
            input_tokens_estimate=tokens_estimate,
        )

        t_end = time.perf_counter()
        total_latency = round((t_end - t0) * 1000, 3)

        return {
            "answers": calibrated_answers,
            "cache_fingerprint": fingerprint,
            "cached": False,
            "calibration": calib_summary,
            "optimization": opt_metadata,
            "success": True,
            "telemetry": {
                "latency_calibration_ms": calib_ms,
                "latency_inference_ms": inference_latency_ms,
                "latency_total_ms": total_latency,
                "mode": "live_evaluation",
                "tokens_consumed": tokens_estimate,
                "tokens_saved": 0,
            },
            "wire_payload": wire_payload,
        }

    def _dispatch_upstream(
        self,
        endpoint: str,
        api_key: str,
        payload: Dict[str, Any],
        timeout: float = 30.0,
        max_retries: int = 3,
        initial_backoff: float = 0.5,
    ) -> Dict[str, Any]:
        raw_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "JevGuard-MCP/1.0",
        }

        attempts = 0
        max_attempts = max(1, max_retries + 1)

        while attempts < max_attempts:
            attempts += 1
            req = urllib.request.Request(endpoint, data=raw_bytes, headers=headers, method="POST")
            t0 = time.perf_counter()

            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    t1 = time.perf_counter()
                    latency_ms = round((t1 - t0) * 1000, 3)
                    body = resp.read().decode("utf-8", errors="replace")
                    data = json.loads(body) if body else {}
                    return {
                        "data": data,
                        "latency_ms": latency_ms,
                        "status_code": resp.getcode(),
                        "success": True,
                    }

            except urllib.error.HTTPError as err:
                code = err.code
                if code in (400, 401, 403, 404):
                    err_body = err.read().decode("utf-8", errors="replace")
                    raise RuntimeError(f"HTTP {code} error from TypeSafe AI: {err_body}")

                if attempts < max_attempts:
                    delay = initial_backoff * (2 ** (attempts - 1)) + random.uniform(0.05, 0.25)
                    time.sleep(delay)
                    continue
                err_body = err.read().decode("utf-8", errors="replace")
                raise RuntimeError(f"HTTP {code} failure after retries: {err_body}")

            except (socket.timeout, TimeoutError) as err:
                if attempts < max_attempts:
                    delay = initial_backoff * (2 ** (attempts - 1)) + random.uniform(0.05, 0.25)
                    time.sleep(delay)
                    continue
                raise RuntimeError(f"Connection timeout to {endpoint}: {err}")

            except Exception as err:
                if attempts < max_attempts:
                    delay = initial_backoff * (2 ** (attempts - 1)) + random.uniform(0.05, 0.25)
                    time.sleep(delay)
                    continue
                raise RuntimeError(f"Network error connecting to TypeSafe AI: {err}")

        raise RuntimeError("Failed to reach TypeSafe AI after maximum retry attempts")
