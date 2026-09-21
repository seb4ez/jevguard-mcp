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
from pathlib import Path
import random
import socket
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
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
    "trace_id",
    "span_id",
    "request_id",
    "correlation_id",
    "nonce",
    "traceid",
    "requestid",
    "x_trace_id",
    "x_request_id",
    "x_correlation_id",
    "xtraceid",
    "xrequestid",
}


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuses to follow HTTP redirects to prevent authorization header leakage."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            newurl, code, f"HTTP redirect ({code}) to '{newurl}' blocked for security.", headers, fp
        )


def is_authorized_endpoint(endpoint: str) -> bool:
    """Strictly validates that endpoint targets an authorized TypeSafe AI hostname without userinfo or spoofing."""
    try:
        parsed = urllib.parse.urlsplit(endpoint.strip())
    except Exception:
        return False

    if parsed.scheme != "https":
        return False

    if parsed.username or parsed.password:
        return False

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return False

    allowed_hosts = {"api.typesafe.ai", "typesafe.ai"}
    custom_allowed = os.environ.get("JEVGUARD_ALLOWED_ENDPOINTS", "")
    if custom_allowed:
        for entry in custom_allowed.split(","):
            entry = entry.strip()
            if entry:
                try:
                    custom_parsed = urllib.parse.urlsplit(entry if "://" in entry else f"https://{entry}")
                    if custom_parsed.hostname:
                        allowed_hosts.add(custom_parsed.hostname.lower())
                except Exception:
                    pass

    return hostname in allowed_hosts


class StatePruner:
    """Removes empty values, nulls, and duplicate whitespace while preventing cycles."""

    @classmethod
    def prune(
        cls,
        data: Any,
        prune_lists: bool = False,
        collapse_whitespace: bool = True,
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
                    pruned_value = cls.prune(value, prune_lists=prune_lists, collapse_whitespace=collapse_whitespace, seen=seen)
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
                        pruned_item = cls.prune(item, prune_lists=prune_lists, collapse_whitespace=collapse_whitespace, seen=seen)
                        if pruned_item is None:
                            continue
                        if isinstance(pruned_item, (str, dict)) and len(pruned_item) == 0:
                            continue
                        pruned_list.append(pruned_item)
                    return pruned_list
                else:
                    return [cls.prune(item, prune_lists=prune_lists, collapse_whitespace=collapse_whitespace, seen=seen) for item in data]

            elif isinstance(data, tuple):
                return tuple(cls.prune(item, prune_lists=prune_lists, collapse_whitespace=collapse_whitespace, seen=seen) for item in data)

            elif isinstance(data, (set, frozenset)):
                pruned_items = [cls.prune(item, prune_lists=prune_lists, collapse_whitespace=collapse_whitespace, seen=seen) for item in data]
                try:
                    return sorted(pruned_items)
                except TypeError:
                    return sorted(pruned_items, key=lambda x: str(x))

            elif isinstance(data, float):
                if math.isnan(data) or math.isinf(data):
                    return None
                return data

            elif isinstance(data, str):
                if collapse_whitespace:
                    if "\n" in data or "\r" in data:
                        return data
                    return " ".join(data.strip().split())
                return data

            return data
        finally:
            if obj_id is not None:
                seen.remove(obj_id)

    @classmethod
    def estimate_tokens(cls, data: Any) -> int:
        if isinstance(data, str):
            return max(1, len(data) // 4)
        raw = json.dumps(data, separators=(",", ":"), default=str)
        return max(1, len(raw) // 4)


def get_default_cache_db_path(custom_path: Optional[str] = None) -> str:
    """
    Returns the canonical SQLite cache database path adhering to L2 caching requirements:
    - Never uses relative paths that pollute the user's active workspace.
    - Defaults to Path.home() / '.cache' / 'jevguard' / 'decision_cache.db'.
    - Honors JEVGUARD_CACHE_PATH environment variable if custom_path is None.
    - If ':memory:', returns ':memory:'.
    - If a relative path is passed (or set via env), resolves it inside ~/.cache/jevguard.
    - Gracefully falls back to ':memory:' upon any filesystem or permission error.
    """
    raw_path = custom_path
    if raw_path is None:
        raw_path = os.environ.get("JEVGUARD_CACHE_PATH")

    if raw_path is not None:
        raw_path = str(raw_path).strip()
        if raw_path == ":memory:":
            return ":memory:"

    try:
        base_dir = Path.home() / ".cache" / "jevguard"
        if raw_path:
            p = Path(raw_path)
            if p.is_absolute():
                target_path = p
            else:
                target_path = base_dir / p
        else:
            target_path = base_dir / "decision_cache.db"

        target_path.parent.mkdir(parents=True, exist_ok=True)
        return str(target_path.resolve())
    except (OSError, PermissionError) as err:
        logger.warning(
            "Permission or filesystem error determining cache db path for '%s': %s. Falling back to ':memory:'.",
            raw_path,
            err,
        )
        return ":memory:"


class DeterministicCache:
    """Provides instant 0-token response retrieval for repeated queries."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        max_memory_items: int = 500,
        default_ignore_keys: Optional[Iterable[str]] = None,
        ttl_seconds: Optional[float] = None,
    ):
        self.db_path = get_default_cache_db_path(db_path)
        self.max_memory_items = max_memory_items
        raw_ttl = os.environ.get("JEVGUARD_CACHE_TTL")
        if raw_ttl is not None:
            try:
                self.ttl_seconds = float(raw_ttl)
            except (ValueError, TypeError):
                self.ttl_seconds = 3600.0
        elif ttl_seconds is not None:
            self.ttl_seconds = float(ttl_seconds)
        else:
            self.ttl_seconds = 3600.0

        self.default_ignore_keys = (
            set(DEFAULT_VOLATILE_KEYS).union({str(k).strip().lower().replace("-", "_") for k in default_ignore_keys})
            if default_ignore_keys is not None
            else set(DEFAULT_VOLATILE_KEYS)
        )
        self._memory_lru: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._local = threading.local()
        self._shared_conn: Optional[sqlite3.Connection] = None

        self.stats = {
            "hits": 0,
            "misses": 0,
            "tokens_saved": 0,
        }

        try:
            if self.db_path == ":memory:":
                self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False, timeout=60.0)
                self._shared_conn.row_factory = sqlite3.Row
                try:
                    self._shared_conn.execute("PRAGMA journal_mode=WAL;")
                    self._shared_conn.execute("PRAGMA synchronous=NORMAL;")
                    self._shared_conn.execute("PRAGMA busy_timeout = 60000;")
                except Exception:
                    pass
            self._init_db()
        except (sqlite3.OperationalError, sqlite3.DatabaseError, OSError, PermissionError) as err:
            logger.warning(
                "SQLite database initialization error at %s (%s). Falling back to ':memory:'.",
                self.db_path,
                err,
            )
            self._fallback_to_memory()

    def _fallback_to_memory(self) -> None:
        with self._lock:
            self.db_path = ":memory:"
            conn = getattr(self._local, "conn", None)
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
                self._local.conn = None
            if self._shared_conn is None:
                self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False, timeout=60.0)
                self._shared_conn.row_factory = sqlite3.Row
                try:
                    self._shared_conn.execute("PRAGMA journal_mode=WAL;")
                    self._shared_conn.execute("PRAGMA synchronous=NORMAL;")
                    self._shared_conn.execute("PRAGMA busy_timeout = 60000;")
                except Exception:
                    pass
                try:
                    self._shared_conn.execute(
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
                    self._shared_conn.commit()
                except Exception as init_err:
                    logger.warning("Error creating table in fallback memory db: %s", init_err)

    @contextlib.contextmanager
    def _get_connection(self):
        if self._shared_conn is not None:
            with self._lock:
                yield self._shared_conn
        else:
            conn = getattr(self._local, "conn", None)
            if conn is None:
                try:
                    conn = sqlite3.connect(self.db_path, timeout=60.0)
                    conn.row_factory = sqlite3.Row
                    try:
                        conn.execute("PRAGMA journal_mode=WAL;")
                        conn.execute("PRAGMA synchronous=NORMAL;")
                        conn.execute("PRAGMA busy_timeout = 60000;")
                    except Exception as err:
                        logger.debug("PRAGMA setup note: %s", err)
                    self._local.conn = conn
                except (sqlite3.OperationalError, sqlite3.DatabaseError, OSError, PermissionError) as err:
                    logger.warning(
                        "SQLite connection error to %s (%s). Falling back to shared :memory:.",
                        self.db_path,
                        err,
                    )
                    self._fallback_to_memory()
                    with self._lock:
                        yield self._shared_conn
                    return
            with self._lock:
                yield conn

    def _init_db(self) -> None:
        try:
            with self._get_connection() as conn:
                try:
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA synchronous=NORMAL;")
                    conn.execute("PRAGMA busy_timeout = 60000;")
                except Exception as err:
                    logger.debug("PRAGMA init note: %s", err)
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
        except (sqlite3.OperationalError, sqlite3.DatabaseError, OSError, PermissionError) as err:
            logger.warning(
                "SQLite _init_db error at %s (%s). Falling back to shared :memory:.",
                self.db_path,
                err,
            )
            self._fallback_to_memory()

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
            elif isinstance(data, float):
                if math.isnan(data) or math.isinf(data):
                    return None
                return data
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
            set(DEFAULT_VOLATILE_KEYS).union({str(k).strip().lower().replace("-", "_") for k in ignore_keys})
            if ignore_keys is not None
            else set(DEFAULT_VOLATILE_KEYS)
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
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    def get(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            if fingerprint in self._memory_lru:
                item = self._memory_lru[fingerprint]
                entry_time = item.get("created_at", 0.0)
                if self.ttl_seconds > 0 and (time.time() - entry_time) > self.ttl_seconds:
                    del self._memory_lru[fingerprint]
                else:
                    self.stats["hits"] += 1
                    tokens = item.get("tokens_estimate", 0)
                    self.stats["tokens_saved"] += tokens
                    self._promote_lru(fingerprint, item["data"], tokens, created_at=entry_time)
                    return item["data"]

        try:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "SELECT response_json, tokens_estimate, created_at FROM evaluation_cache WHERE fingerprint = ?",
                    (fingerprint,),
                )
                row = cur.fetchone()
                if row:
                    entry_created_at = row["created_at"]
                    if self.ttl_seconds > 0 and (time.time() - entry_created_at) > self.ttl_seconds:
                        conn.execute("DELETE FROM evaluation_cache WHERE fingerprint = ?", (fingerprint,))
                        conn.commit()
                    else:
                        with self._lock:
                            self.stats["hits"] += 1
                            data = json.loads(row["response_json"])
                            tokens = row["tokens_estimate"]
                            self.stats["tokens_saved"] += tokens
                            self._promote_lru(fingerprint, data, tokens, created_at=entry_created_at)
                        return data
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as err:
            logger.warning("Cache lookup database error for %s: %s. Falling back to :memory:.", fingerprint, err)
            self._fallback_to_memory()
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
        now = time.time()
        try:
            raw_json = json.dumps(response_data, separators=(",", ":"), default=str)
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
                        now,
                        fingerprint,
                        input_tokens_estimate,
                    ),
                )
                conn.commit()

            with self._lock:
                self._promote_lru(fingerprint, response_data, input_tokens_estimate, created_at=now)
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as err:
            logger.warning("Cache write database error for %s: %s. Falling back to :memory:.", fingerprint, err)
            self._fallback_to_memory()
            try:
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
                            now,
                            fingerprint,
                            input_tokens_estimate,
                        ),
                    )
                    conn.commit()
                with self._lock:
                    self._promote_lru(fingerprint, response_data, input_tokens_estimate, created_at=now)
            except Exception as retry_err:
                logger.warning("In-memory cache write retry error: %s", retry_err)
        except Exception as err:
            logger.warning("Cache write error for %s: %s", fingerprint, err)

    def _promote_lru(
        self,
        fingerprint: str,
        data: Dict[str, Any],
        tokens_estimate: int,
        created_at: Optional[float] = None,
    ) -> None:
        if fingerprint in self._memory_lru:
            existing = self._memory_lru.pop(fingerprint)
            hit_count = existing.get("hit_count", 0) + 1
            entry_time = existing.get("created_at", created_at or time.time())
        else:
            hit_count = 0
            entry_time = created_at or time.time()

        if len(self._memory_lru) >= self.max_memory_items:
            oldest_key = next(iter(self._memory_lru))
            del self._memory_lru[oldest_key]

        self._memory_lru[fingerprint] = {
            "data": data,
            "hit_count": hit_count,
            "tokens_estimate": tokens_estimate,
            "created_at": entry_time,
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
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as err:
            logger.warning("Cache clear database error: %s. Falling back to :memory:.", err)
            self._fallback_to_memory()
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
                calibrated[name] = {
                    "is_ambiguous": True,
                    "status": "AMBIGUOUS_STATE",
                    "calibration": {"reasons": ["invalid_answer_structure"]},
                    "raw": ans,
                }
                ambiguous_questions.append(name)
                continue

            item = dict(ans)
            q_type = str(item.get("type", "")).strip().lower()

            if q_type == "choice":
                self._calibrate_choice(item)
            elif q_type == "score":
                self._calibrate_score(item)
            elif q_type == "noul":
                self._calibrate_noul(item)
            else:
                item["is_ambiguous"] = True
                item["status"] = "AMBIGUOUS_STATE"
                item["calibration"] = {
                    "reasons": ["unknown_question_type"],
                    "question_type": q_type,
                }

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
        has_invalid = False
        if isinstance(probs, dict):
            for k, v in probs.items():
                try:
                    val = float(v)
                    if math.isnan(val) or math.isinf(val):
                        has_invalid = True
                    else:
                        parsed_pairs.append((str(k), val))
                except (ValueError, TypeError):
                    has_invalid = True

        if not parsed_pairs:
            try:
                raw_conf = item.get("confidence", 0.0)
                conf = float(raw_conf)
                if math.isnan(conf) or math.isinf(conf):
                    conf = 0.0
                    has_invalid = True
            except (ValueError, TypeError):
                conf = 0.0
                has_invalid = True

            reasons = []
            if has_invalid:
                reasons.append("invalid_probability")
            if conf < self.min_top_prob:
                reasons.append("low_confidence")

            is_amb = len(reasons) > 0
            item["is_ambiguous"] = is_amb
            item["status"] = "AMBIGUOUS_STATE" if is_amb else "CONFIDENT"
            item["calibration"] = {
                "dispersion_gap": round(conf, 4),
                "reasons": reasons,
                "runner_up_choice": None,
                "runner_up_probability": 0.0,
                "top_choice": item.get("choice"),
                "top_probability": round(conf, 4),
            }
            return

        sorted_pairs = sorted(parsed_pairs, key=lambda x: x[1], reverse=True)
        top_k, top_p = sorted_pairs[0]
        runner_k, runner_p = sorted_pairs[1] if len(sorted_pairs) > 1 else (None, 0.0)
        gap = top_p - runner_p

        reasons: List[str] = []
        if has_invalid:
            reasons.append("invalid_probability")
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
        reasons: List[str] = []
        raw_conf = item.get("confidence")
        if raw_conf is None:
            conf = 0.0
            reasons.append("low_confidence")
        else:
            try:
                conf = float(raw_conf)
                if math.isnan(conf) or math.isinf(conf):
                    conf = 0.0
                    reasons.append("invalid_probability")
            except (ValueError, TypeError):
                conf = 0.0
                reasons.append("invalid_probability")

        probs = item.get("probabilities", {})

        if conf < self.min_top_prob and "low_confidence" not in reasons:
            reasons.append("low_confidence")

        dispersion_gap = conf
        if isinstance(probs, dict) and len(probs) >= 2:
            parsed_probs: List[float] = []
            for v in probs.values():
                try:
                    val = float(v)
                    if math.isnan(val) or math.isinf(val):
                        if "invalid_probability" not in reasons:
                            reasons.append("invalid_probability")
                    else:
                        parsed_probs.append(val)
                except (ValueError, TypeError):
                    if "invalid_probability" not in reasons:
                        reasons.append("invalid_probability")
            if len(parsed_probs) >= 2:
                sorted_probs = sorted(parsed_probs, reverse=True)
                top_p = sorted_probs[0]
                runner_p = sorted_probs[1]
                dispersion_gap = top_p - runner_p
                if top_p < self.min_top_prob and "low_confidence" not in reasons:
                    reasons.append("low_confidence")
                if dispersion_gap < self.min_dispersion_gap and "flat_distribution" not in reasons:
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
            item["is_ambiguous"] = True
            item["status"] = "AMBIGUOUS_STATE"
            item["calibration"] = {
                "boundary_distance": 0.0,
                "probability": 0.0,
                "reasons": ["missing_noul_value"],
            }
            return
        try:
            prob = float(val)
        except (ValueError, TypeError):
            item["is_ambiguous"] = True
            item["status"] = "AMBIGUOUS_STATE"
            item["calibration"] = {
                "boundary_distance": 0.0,
                "probability": 0.0,
                "reasons": ["invalid_probability"],
            }
            return

        if math.isnan(prob) or math.isinf(prob):
            item["is_ambiguous"] = True
            item["status"] = "AMBIGUOUS_STATE"
            item["calibration"] = {
                "boundary_distance": 0.0,
                "probability": 0.0,
                "reasons": ["invalid_probability"],
            }
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
            criteria = q.get("criteria")
            if criteria is None:
                criteria = []
            elif not isinstance(criteria, list):
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
            allow_esc_opt = q.get("auto_inject_escape")
            if allow_esc_opt is None:
                allow_esc_opt = q.get("auto_inject_escapes")
            allow_escape = bool(allow_esc_opt) if allow_esc_opt is not None else (not closed)
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

    def __init__(self, cache_db_path: Optional[str] = None, allow_test_mocks: bool = False):
        self._lock = threading.RLock()
        self.cache = DeterministicCache(db_path=cache_db_path)
        self.optimizer = QuestionOptimizer()
        self.calibrator = ResponseCalibrator()
        self.allow_test_mocks = allow_test_mocks or (os.environ.get("JEVGUARD_TEST_MODE") == "1")

    def get_definitions(self) -> List[Dict[str, Any]]:
        with self._lock:
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
                            "type": "object",
                            "description": "Input state payload dictionary or structure to evaluate against criteria.",
                        },
                        "questions": {
                            "type": "object",
                            "description": "Dictionary of question definitions mapping question keys to criteria (noul, score, choice).",
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
                        "timeout": {
                            "type": "number",
                            "description": "HTTP request timeout in seconds (default: 30.0).",
                            "default": 30.0,
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
                            "type": "object",
                            "description": "The state payload dictionary or structure to sanitize and prune.",
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
                            "type": "object",
                            "description": "State payload dictionary to include in fingerprint computation.",
                        },
                        "questions": {
                            "type": "object",
                            "description": "Question definitions dictionary (optional).",
                        },
                        "model": {
                            "type": "string",
                            "description": "Target model identifier (default: jev-latest).",
                            "default": "jev-latest",
                        },
                        "auto_inject_escapes": {
                            "type": "boolean",
                            "description": "Whether to consider escape injection logic when computing fingerprint (default: true).",
                            "default": True,
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
            {
                "name": "evaluate_command_safety",
                "description": (
                    "Evaluates terminal/shell command safety for autonomous agents. Determines whether a command "
                    "is destructive, requires human approval, or can execute autonomously using Noul, Score, "
                    "and Choice certainty calibration. Returns policy: ALLOW_AUTONOMOUS, REQUIRE_HUMAN_APPROVAL, or DENY_DESTRUCTIVE."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Terminal command string to evaluate.",
                        },
                        "working_dir": {
                            "type": "string",
                            "description": "Working directory for execution context (optional).",
                            "default": "",
                        },
                        "elevated_privileges": {
                            "type": "boolean",
                            "description": "Whether execution uses sudo or administrative privileges (optional, default: false).",
                            "default": False,
                        },
                        "timeout": {
                            "type": "number",
                            "description": "HTTP request timeout in seconds (default: 30.0).",
                            "default": 30.0,
                        },
                        "bypass_cache": {
                            "type": "boolean",
                            "description": "Bypass deterministic cache lookup.",
                            "default": True,
                        },
                    },
                    "required": ["command"],
                },
            },
            {
                "name": "verify_code_patch",
                "description": (
                    "Evaluates whether a code diff or patch introduces security regressions, broken syntax, "
                    "or critical system impact under a configurable risk tolerance (strict, balanced, permissive)."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "patch_content": {
                            "type": "string",
                            "description": "Diff or patch content to verify.",
                        },
                        "target_file": {
                            "type": "string",
                            "description": "Path of the target file being modified.",
                        },
                        "risk_tolerance": {
                            "type": "string",
                            "enum": ["strict", "balanced", "permissive"],
                            "description": "Risk tolerance threshold for acceptance (strict, balanced, permissive; default: balanced).",
                            "default": "balanced",
                        },
                        "timeout": {
                            "type": "number",
                            "description": "HTTP request timeout in seconds (default: 30.0).",
                            "default": 30.0,
                        },
                        "bypass_cache": {
                            "type": "boolean",
                            "description": "Bypass deterministic cache lookup.",
                            "default": True,
                        },
                    },
                    "required": ["patch_content", "target_file"],
                },
            },
            {
                "name": "evaluate_decision",
                "description": (
                    "Evaluates architectural and implementation decisions with a simple list of options. "
                    "Automatically injects closed-world neutral escape (UNRESOLVED_OR_OTHER) and calibrates probability dispersion."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "context": {
                            "type": "string",
                            "description": "Context and constraints surrounding the decision.",
                        },
                        "decision_question": {
                            "type": "string",
                            "description": "The specific question or decision to evaluate.",
                        },
                        "options": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Candidate options list (e.g. ['A', 'B', 'C']).",
                        },
                        "timeout": {
                            "type": "number",
                            "description": "HTTP request timeout in seconds (default: 30.0).",
                            "default": 30.0,
                        },
                        "bypass_cache": {
                            "type": "boolean",
                            "description": "Bypass deterministic cache lookup.",
                            "default": False,
                        },
                    },
                    "required": ["context", "decision_question", "options"],
                },
            },
        ]

    def get_tool_allowed_properties(self, tool_name: str) -> Optional[Set[str]]:
        for item in self.get_definitions():
            if item.get("name") == tool_name:
                schema = item.get("inputSchema", {})
                props = schema.get("properties", {})
                return set(props.keys())
        return None

    def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            if not isinstance(arguments, dict):
                return {
                    "status": "error",
                    "success": False,
                    "error_type": "ValueError",
                    "message": f"Tool arguments must be a dictionary, got {type(arguments).__name__}",
                    "verdict": "MANUAL_REVIEW_REQUIRED",
                    "fallback_action": "MANUAL_REVIEW_REQUIRED",
                }

            handler_map = {
                "jevguard_prune_state": self._tool_prune_state,
                "jevguard_cache_fingerprint": self._tool_cache_fingerprint,
                "jevguard_calibrate": self._tool_calibrate,
                "jevguard_evaluate": self._tool_evaluate,
                "evaluate_command_safety": self._tool_evaluate_command_safety,
                "verify_code_patch": self._tool_verify_code_patch,
                "evaluate_decision": self._tool_evaluate_decision,
            }

            if name not in handler_map:
                raise KeyError(f"Unknown tool: '{name}'")

            allowed_keys = self.get_tool_allowed_properties(name)
            if allowed_keys is not None:
                is_test = self.allow_test_mocks or (os.environ.get("JEVGUARD_TEST_MODE") == "1")
                extra_keys = set(arguments.keys()) - allowed_keys
                if not is_test:
                    if "mock_answers" in extra_keys or "_mock_answers" in extra_keys:
                        return {
                            "status": "error",
                            "success": False,
                            "error_type": "SecurityError",
                            "message": "Direct mock_answers injection is forbidden in production MCP server.",
                            "verdict": "MANUAL_REVIEW_REQUIRED",
                            "fallback_action": "MANUAL_REVIEW_REQUIRED",
                        }
                    if extra_keys:
                        return {
                            "status": "error",
                            "success": False,
                            "error_type": "ValidationError",
                            "message": f"Unrecognized arguments for tool '{name}': {sorted(list(extra_keys))}",
                            "verdict": "MANUAL_REVIEW_REQUIRED",
                            "fallback_action": "MANUAL_REVIEW_REQUIRED",
                        }
                else:
                    test_allowed = {"mock_answers", "_mock_answers"}
                    unrecognized = extra_keys - test_allowed
                    if unrecognized:
                        return {
                            "status": "error",
                            "success": False,
                            "error_type": "ValidationError",
                            "message": f"Unrecognized arguments for tool '{name}': {sorted(list(unrecognized))}",
                            "verdict": "MANUAL_REVIEW_REQUIRED",
                            "fallback_action": "MANUAL_REVIEW_REQUIRED",
                        }

            handler = handler_map[name]
            try:
                return handler(arguments)
            except Exception as err:
                logger.warning("Tool execution error in '%s': %s", name, err)
                return {
                    "status": "error",
                    "success": False,
                    "error_type": type(err).__name__,
                    "message": str(err),
                    "verdict": "MANUAL_REVIEW_REQUIRED",
                    "fallback_action": "MANUAL_REVIEW_REQUIRED",
                }

    def close(self) -> None:
        with self._lock:
            self.cache.close()

    def _tool_prune_state(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if "state" not in arguments:
                raise ValueError("Missing required argument: 'state'")
            state = arguments["state"]
            prune_lists = bool(arguments.get("prune_lists", False))

            pruned = StatePruner.prune(state, prune_lists=prune_lists)
            tokens_estimate = StatePruner.estimate_tokens(pruned)
            return {
                "success": True,
                "estimated_tokens": tokens_estimate,
                "pruned_state": pruned,
            }
        except Exception as err:
            logger.warning("Error in jevguard_prune_state: %s", err)
            return {
                "status": "error",
                "success": False,
                "error_type": type(err).__name__,
                "message": str(err),
                "verdict": "MANUAL_REVIEW_REQUIRED",
                "fallback_action": "MANUAL_REVIEW_REQUIRED",
            }

    def _tool_cache_fingerprint(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if "state" not in arguments:
                raise ValueError("Missing required argument: 'state'")
            state = arguments["state"]
            questions = arguments.get("questions") or {}
            model = str(arguments.get("model", "jev-latest")).strip() or "jev-latest"
            auto_inject = bool(arguments.get("auto_inject_escapes", True))
            ignore_keys = arguments.get("ignore_keys")

            wire_questions = questions
            if isinstance(questions, (dict, list)) and questions:
                try:
                    wire_questions, _ = self.optimizer.normalize_questions(questions, auto_inject_escapes=auto_inject)
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
                "success": True,
                "fingerprint": fp,
                "masked_volatile_keys": keys_used,
                "model": model,
            }
        except Exception as err:
            logger.warning("Error in jevguard_cache_fingerprint: %s", err)
            return {
                "status": "error",
                "success": False,
                "error_type": type(err).__name__,
                "message": str(err),
                "verdict": "MANUAL_REVIEW_REQUIRED",
                "fallback_action": "MANUAL_REVIEW_REQUIRED",
            }

    def _tool_calibrate(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
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
                "success": True,
                "calibrated_answers": calibrated_answers,
                "summary": summary,
            }
        except Exception as err:
            logger.warning("Error in jevguard_calibrate: %s", err)
            return {
                "status": "error",
                "success": False,
                "error_type": type(err).__name__,
                "message": str(err),
                "verdict": "MANUAL_REVIEW_REQUIRED",
                "fallback_action": "MANUAL_REVIEW_REQUIRED",
            }

    def _tool_evaluate(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if "state" not in arguments:
                raise ValueError("Missing required argument: 'state'")
            if "questions" not in arguments:
                raise ValueError("Missing required argument: 'questions'")

            state = arguments["state"]
            questions = arguments["questions"]
            model = str(arguments.get("model", "jev-latest")).strip() or "jev-latest"
            auto_inject = bool(arguments.get("auto_inject_escapes", True))
            bypass_cache = bool(arguments.get("bypass_cache", False))
            timeout = float(arguments.get("timeout", 30.0))

            # Security: Never accept API key from client/LLM arguments
            api_key = str(os.environ.get("TYPESAFE_API_KEY", "")).strip()

            # Security: Endpoint is governed by server environment configuration
            endpoint = str(os.environ.get("TYPESAFE_ENDPOINT") or os.environ.get("JEVGUARD_ENDPOINT") or "https://api.typesafe.ai/v1/systemone").strip()

            # Security: mock_answers is forbidden in production to prevent verdict forgery
            is_test = self.allow_test_mocks or (os.environ.get("JEVGUARD_TEST_MODE") == "1")
            mock_answers = arguments.get("mock_answers") or arguments.get("_mock_answers")
            if mock_answers is not None and not is_test:
                return {
                    "status": "error",
                    "success": False,
                    "error_type": "SecurityError",
                    "message": "Direct mock_answers injection is forbidden in production MCP server.",
                    "verdict": "MANUAL_REVIEW_REQUIRED",
                    "fallback_action": "MANUAL_REVIEW_REQUIRED",
                }

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
                    "status": "error",
                    "success": False,
                    "error": "TYPESAFE_API_KEY not configured in MCP settings or environment",
                    "error_type": "ConfigurationError",
                    "message": "TYPESAFE_API_KEY not configured in MCP settings or environment",
                    "verdict": "MANUAL_REVIEW_REQUIRED",
                    "fallback_action": "MANUAL_REVIEW_REQUIRED",
                    "cache_fingerprint": fingerprint,
                    "wire_payload": wire_payload,
                    "optimization": opt_metadata,
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
        except Exception as err:
            logger.warning("Error in jevguard_evaluate: %s", err)
            return {
                "status": "error",
                "success": False,
                "error_type": type(err).__name__,
                "message": str(err),
                "verdict": "MANUAL_REVIEW_REQUIRED",
                "fallback_action": "MANUAL_REVIEW_REQUIRED",
            }

    def _tool_evaluate_command_safety(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if "command" not in arguments:
                raise ValueError("Missing required argument: 'command'")
            command = arguments["command"]
            if not isinstance(command, str) or not command.strip():
                raise ValueError("Argument 'command' must be a non-empty string")

            working_dir = str(arguments.get("working_dir", "") or "").strip()
            elevated = bool(arguments.get("elevated_privileges", False))
            mock_answers = (
                arguments.get("mock_answers")
                if (self.allow_test_mocks or os.environ.get("JEVGUARD_TEST_MODE") == "1")
                else None
            )
            timeout = float(arguments.get("timeout", 30.0))
            bypass_cache = bool(arguments.get("bypass_cache", True))

            state = {
                "command": command,
                "working_dir": working_dir,
                "elevated_privileges": elevated,
            }

            questions = {
                "is_destructive": {
                    "type": "noul",
                    "instructions": (
                        "Determine if the command performs irreversible filesystem deletion, system formatting, "
                        "kill process, partition modification, or critical destruction."
                    ),
                },
                "risk_score": {
                    "type": "score",
                    "instructions": "Rate the blast radius and operational risk of executing this terminal command.",
                    "criteria": [
                        "Read-only or harmless diagnostic (ls, pwd, echo, cat, git status)",
                        "Low-risk non-destructive build/test (make test, pytest, cargo check)",
                        "Moderate-risk state mutation (git checkout, npm install, pip install)",
                        "High-risk system modification (systemctl, kill, useradd, iptables)",
                        "Critical destructive action (rm -rf, dd, mkfs, format, DROP DATABASE)",
                    ],
                },
                "execution_policy": {
                    "type": "choice",
                    "instructions": "Select the appropriate execution policy for autonomous agent execution.",
                    "criteria": {
                        "ALLOW_AUTONOMOUS": "Safe to execute automatically without human intervention",
                        "REQUIRE_HUMAN_APPROVAL": "Requires explicit human confirmation before execution",
                        "DENY_DESTRUCTIVE": "Dangerous or destructive; execution denied",
                    },
                    "closed_world": True,
                    "auto_inject_escape": True,
                },
            }

            eval_payload = {
                "state": state,
                "questions": questions,
                "timeout": timeout,
                "bypass_cache": bypass_cache,
            }
            if mock_answers is not None:
                eval_payload["mock_answers"] = mock_answers

            eval_res = self._tool_evaluate(eval_payload)

            if not eval_res.get("success", False):
                return {
                    "status": "error",
                    "success": False,
                    "error_type": eval_res.get("error_type", "EvaluationError"),
                    "message": eval_res.get("message") or eval_res.get("error", "Evaluation failed"),
                    "verdict": "MANUAL_REVIEW_REQUIRED",
                    "fallback_action": "MANUAL_REVIEW_REQUIRED",
                    "policy": "REQUIRE_HUMAN_APPROVAL",
                    "command": command,
                    "cache_fingerprint": eval_res.get("cache_fingerprint"),
                }

            answers = eval_res.get("answers", {})
            calib = eval_res.get("calibration", {})
            has_ambiguity = calib.get("has_ambiguity", False)

            noul_item = answers.get("is_destructive", {})
            noul_val = noul_item.get("noul")
            if noul_val is None:
                noul_val = noul_item.get("calibration", {}).get("probability")
            try:
                noul_prob = float(noul_val) if noul_val is not None else None
            except (ValueError, TypeError):
                noul_prob = None

            choice_item = answers.get("execution_policy", {})
            raw_choice = choice_item.get("choice")

            if raw_choice == "DENY_DESTRUCTIVE" or (noul_prob is not None and noul_prob >= 0.70):
                policy = "DENY_DESTRUCTIVE"
            elif elevated or has_ambiguity or noul_prob is None or noul_prob >= 0.35 or raw_choice != "ALLOW_AUTONOMOUS":
                policy = "REQUIRE_HUMAN_APPROVAL"
            elif raw_choice == "ALLOW_AUTONOMOUS" and not elevated and not has_ambiguity and (noul_prob is not None and noul_prob < 0.35):
                policy = "ALLOW_AUTONOMOUS"
            else:
                policy = "REQUIRE_HUMAN_APPROVAL"

            return {
                "success": True,
                "policy": policy,
                "command": command,
                "working_dir": working_dir,
                "elevated_privileges": elevated,
                "verdict": {
                    "policy": policy,
                    "is_destructive_probability": round(noul_prob, 4) if noul_prob is not None else 0.0,
                    "raw_choice": raw_choice,
                    "ambiguity_detected": has_ambiguity,
                    "requires_human": policy != "ALLOW_AUTONOMOUS",
                },
                "calibration": calib,
                "answers": answers,
                "cache_fingerprint": eval_res.get("cache_fingerprint"),
                "cached": eval_res.get("cached", False),
                "telemetry": eval_res.get("telemetry"),
            }
        except Exception as err:
            logger.warning("Error evaluating command safety: %s", err)
            return {
                "status": "error",
                "success": False,
                "error_type": type(err).__name__,
                "message": str(err),
                "verdict": "MANUAL_REVIEW_REQUIRED",
                "fallback_action": "MANUAL_REVIEW_REQUIRED",
            }

    def _tool_verify_code_patch(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if "patch_content" not in arguments:
                raise ValueError("Missing required argument: 'patch_content'")
            if "target_file" not in arguments:
                raise ValueError("Missing required argument: 'target_file'")

            patch_content = arguments["patch_content"]
            if not isinstance(patch_content, str) or not patch_content.strip():
                raise ValueError("Argument 'patch_content' must be a non-empty string")

            target_file = arguments["target_file"]
            if not isinstance(target_file, str) or not target_file.strip():
                raise ValueError("Argument 'target_file' must be a non-empty string")

            risk_tolerance = str(arguments.get("risk_tolerance", "balanced")).strip().lower()
            if risk_tolerance not in ("strict", "balanced", "permissive"):
                raise ValueError("Argument 'risk_tolerance' must be one of: strict, balanced, permissive")

            mock_answers = (
                arguments.get("mock_answers")
                if (self.allow_test_mocks or os.environ.get("JEVGUARD_TEST_MODE") == "1")
                else None
            )
            timeout = float(arguments.get("timeout", 30.0))
            bypass_cache = bool(arguments.get("bypass_cache", True))

            state = {
                "patch_content": patch_content,
                "target_file": target_file.strip(),
                "risk_tolerance": risk_tolerance,
            }

            questions = {
                "has_regression": {
                    "type": "noul",
                    "instructions": (
                        f"Determine if the patch applied to '{target_file}' introduces security regressions, "
                        "syntax errors, injection flaws, memory leaks, or breaking behavior."
                    ),
                },
                "risk_score": {
                    "type": "score",
                    "instructions": "Rate the blast radius and risk score of the modifications in this patch.",
                    "criteria": [
                        "Clean, safe patch with zero regressions (documentation, trivial bugfix)",
                        "Low risk (isolated helper function, test additions)",
                        "Moderate risk (core business logic, state schema mutation)",
                        "High risk (authentication, cryptography, networking, concurrency)",
                        "Critical vulnerability, syntax error, or breaking regression",
                    ],
                },
                "recommendation": {
                    "type": "choice",
                    "instructions": f"Determine verification verdict under '{risk_tolerance}' tolerance.",
                    "criteria": {
                        "APPROVE": "Patch is safe to merge and apply autonomously",
                        "REQUEST_CHANGES": "Patch introduces potential risks or requires human review",
                        "REJECT": "Patch contains dangerous flaws, regressions, or syntax errors",
                    },
                    "closed_world": True,
                    "auto_inject_escape": True,
                },
            }

            eval_payload = {
                "state": state,
                "questions": questions,
                "timeout": timeout,
                "bypass_cache": bypass_cache,
            }
            if mock_answers is not None:
                eval_payload["mock_answers"] = mock_answers

            eval_res = self._tool_evaluate(eval_payload)

            if not eval_res.get("success", False):
                return {
                    "status": "error",
                    "success": False,
                    "error_type": eval_res.get("error_type", "EvaluationError"),
                    "message": eval_res.get("message") or eval_res.get("error", "Evaluation failed"),
                    "verdict": "MANUAL_REVIEW_REQUIRED",
                    "fallback_action": "MANUAL_REVIEW_REQUIRED",
                    "approved": False,
                    "recommendation": "REQUEST_CHANGES",
                    "target_file": target_file,
                    "cache_fingerprint": eval_res.get("cache_fingerprint"),
                }

            answers = eval_res.get("answers", {})
            calib = eval_res.get("calibration", {})
            has_ambiguity = calib.get("has_ambiguity", False)

            noul_item = answers.get("has_regression", {})
            noul_val = noul_item.get("noul")
            if noul_val is None:
                noul_val = noul_item.get("calibration", {}).get("probability")
            try:
                noul_prob = float(noul_val) if noul_val is not None else None
            except (ValueError, TypeError):
                noul_prob = None

            choice_item = answers.get("recommendation", {})
            raw_rec = choice_item.get("choice")

            if raw_rec == "REJECT" or (noul_prob is not None and noul_prob >= 0.70):
                rec = "REJECT"
                approved = False
                risk_level = "CRITICAL" if (noul_prob and noul_prob >= 0.85) else "HIGH"
            elif has_ambiguity or noul_prob is None or raw_rec != "APPROVE":
                rec = "REQUEST_CHANGES"
                approved = False
                risk_level = "MEDIUM"
            elif risk_tolerance == "strict" and noul_prob >= 0.20:
                rec = "REQUEST_CHANGES"
                approved = False
                risk_level = "MEDIUM"
            elif risk_tolerance == "balanced" and noul_prob >= 0.40:
                rec = "REQUEST_CHANGES"
                approved = False
                risk_level = "MEDIUM"
            elif risk_tolerance == "permissive" and noul_prob >= 0.60:
                rec = "REQUEST_CHANGES"
                approved = False
                risk_level = "MEDIUM"
            else:
                rec = "APPROVE"
                approved = True
                risk_level = "LOW"

            return {
                "success": True,
                "approved": approved,
                "recommendation": rec,
                "risk_level": risk_level,
                "target_file": target_file,
                "risk_tolerance": risk_tolerance,
                "verdict": {
                    "approved": approved,
                    "recommendation": rec,
                    "risk_level": risk_level,
                    "regression_probability": round(noul_prob, 4) if noul_prob is not None else 0.0,
                    "raw_choice": raw_rec,
                    "ambiguity_detected": has_ambiguity,
                },
                "calibration": calib,
                "answers": answers,
                "cache_fingerprint": eval_res.get("cache_fingerprint"),
                "cached": eval_res.get("cached", False),
                "telemetry": eval_res.get("telemetry"),
            }
        except Exception as err:
            logger.warning("Error verifying code patch: %s", err)
            return {
                "status": "error",
                "success": False,
                "error_type": type(err).__name__,
                "message": str(err),
                "verdict": "MANUAL_REVIEW_REQUIRED",
                "fallback_action": "MANUAL_REVIEW_REQUIRED",
            }

    def _tool_evaluate_decision(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if "context" not in arguments:
                raise ValueError("Missing required argument: 'context'")
            if "decision_question" not in arguments:
                raise ValueError("Missing required argument: 'decision_question'")
            if "options" not in arguments:
                raise ValueError("Missing required argument: 'options'")

            context = arguments["context"]
            if not isinstance(context, str) or not context.strip():
                raise ValueError("Argument 'context' must be a non-empty string")

            decision_question = arguments["decision_question"]
            if not isinstance(decision_question, str) or not decision_question.strip():
                raise ValueError("Argument 'decision_question' must be a non-empty string")

            raw_options = arguments["options"]
            if not isinstance(raw_options, (list, tuple)):
                raise ValueError("Argument 'options' must be a list of string options")

            options = [str(opt).strip() for opt in raw_options if str(opt).strip()]
            if len(options) < 1:
                raise ValueError("Argument 'options' must contain at least one option")

            mock_answers = (
                arguments.get("mock_answers")
                if (self.allow_test_mocks or os.environ.get("JEVGUARD_TEST_MODE") == "1")
                else None
            )
            timeout = float(arguments.get("timeout", 30.0))
            bypass_cache = bool(arguments.get("bypass_cache", False))

            state = {
                "context": context.strip(),
                "decision_question": decision_question.strip(),
                "options": options,
            }

            questions = {
                "decision": {
                    "type": "choice",
                    "instructions": decision_question.strip(),
                    "criteria": {opt: opt for opt in options},
                    "closed_world": True,
                    "auto_inject_escape": True,
                }
            }

            eval_payload = {
                "state": state,
                "questions": questions,
                "timeout": timeout,
                "bypass_cache": bypass_cache,
            }
            if mock_answers is not None:
                eval_payload["mock_answers"] = mock_answers

            eval_res = self._tool_evaluate(eval_payload)

            if not eval_res.get("success", False):
                return {
                    "status": "error",
                    "success": False,
                    "error_type": eval_res.get("error_type", "EvaluationError"),
                    "message": eval_res.get("message") or eval_res.get("error", "Evaluation failed"),
                    "verdict": "MANUAL_REVIEW_REQUIRED",
                    "fallback_action": "MANUAL_REVIEW_REQUIRED",
                    "decision_question": decision_question,
                    "options": options,
                    "cache_fingerprint": eval_res.get("cache_fingerprint"),
                }

            answers = eval_res.get("answers", {})
            decision_ans = answers.get("decision", {})
            selected_choice = decision_ans.get("choice")
            confidence = decision_ans.get("confidence", 0.0)
            is_ambiguous = decision_ans.get("is_ambiguous", False)
            status = decision_ans.get("status", "CONFIDENT")
            is_escape = selected_choice == ESCAPE_OPTION_KEY

            return {
                "success": True,
                "decision_question": decision_question,
                "selected_option": selected_choice,
                "confidence": confidence,
                "is_ambiguous": is_ambiguous,
                "is_escape_selected": is_escape,
                "status": status,
                "options": options,
                "context": context,
                "calibration": decision_ans.get("calibration", {}),
                "answers": answers,
                "cache_fingerprint": eval_res.get("cache_fingerprint"),
                "cached": eval_res.get("cached", False),
                "telemetry": eval_res.get("telemetry"),
            }
        except Exception as err:
            logger.warning("Error evaluating decision: %s", err)
            return {
                "status": "error",
                "success": False,
                "error_type": type(err).__name__,
                "message": str(err),
                "verdict": "MANUAL_REVIEW_REQUIRED",
                "fallback_action": "MANUAL_REVIEW_REQUIRED",
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
        canonical_endpoint = str(endpoint).strip()
        if not is_authorized_endpoint(canonical_endpoint):
            raise PermissionError(
                f"Endpoint '{canonical_endpoint}' is not permitted. Only official TypeSafe AI endpoints or JEVGUARD_ALLOWED_ENDPOINTS are authorized."
            )

        raw_bytes = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "JevGuard-MCP/1.0",
        }

        attempts = 0
        max_attempts = max(1, max_retries + 1)
        opener = urllib.request.build_opener(NoRedirectHandler())

        while attempts < max_attempts:
            attempts += 1
            req = urllib.request.Request(endpoint, data=raw_bytes, headers=headers, method="POST")
            t0 = time.perf_counter()

            try:
                with opener.open(req, timeout=timeout) as resp:
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
                try:
                    err_body = err.read().decode("utf-8", errors="replace")
                except Exception:
                    err_body = str(err)
                if code in (400, 401, 403, 404):
                    raise RuntimeError(f"HTTP {code} error from TypeSafe AI: {err_body}")

                if attempts < max_attempts:
                    delay = initial_backoff * (2 ** (attempts - 1)) + random.uniform(0.05, 0.25)
                    time.sleep(delay)
                    continue
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
