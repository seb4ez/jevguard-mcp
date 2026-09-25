"""
JevGuard MCP Tools - Tool registration and execution engine.
Implements state pruning, closed-world escape injection, certainty calibration,
canonical SHA-256 fingerprinting, hardened caching, and deterministic evaluation.
All operations rely solely on the Python standard library.
"""

import contextlib
import copy
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
                if any(c in entry for c in "*?[]"):
                    continue
                try:
                    custom_parsed = urllib.parse.urlsplit(entry if "://" in entry else f"https://{entry}")
                    if custom_parsed.hostname and not any(c in custom_parsed.hostname for c in "*?[]"):
                        allowed_hosts.add(custom_parsed.hostname.lower())
                except Exception:
                    pass

    return hostname in allowed_hosts


def _sanitize_bool(val: Any, field_name: str = "field") -> bool:
    """Strictly validates and casts a boolean parameter, preventing 'false' from becoming True."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        v = val.strip().lower()
        if v in ("true", "1", "yes", "on"):
            return True
        elif v in ("false", "0", "no", "off", ""):
            return False
        raise ValueError(f"Invalid boolean value for '{field_name}': '{val}'")
    if isinstance(val, (int, float)):
        if val == 1:
            return True
        elif val == 0:
            return False
        raise ValueError(f"Invalid numeric boolean for '{field_name}': {val}")
    raise ValueError(f"Invalid type for boolean field '{field_name}': {type(val).__name__}")


def is_escape_selected(choice: Any) -> bool:
    """Checks whether a selected choice represents a neutral escape candidate."""
    if not isinstance(choice, str):
        return False
    c = choice.strip().lower()
    return c in ESCAPE_CANDIDATE_KEYS or c == ESCAPE_OPTION_KEY.lower()


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
    - If a relative path is passed (or set via env), resolves it inside ~/.cache/jevguard without escaping via '..'.
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
        base_dir = (Path.home() / ".cache" / "jevguard").resolve()
        if raw_path:
            p = Path(raw_path)
            if p.is_absolute():
                target_path = p.resolve()
            else:
                candidate = (base_dir / p).resolve()
                try:
                    candidate.relative_to(base_dir)
                    target_path = candidate
                except ValueError:
                    target_path = base_dir / p.name
        else:
            target_path = base_dir / "decision_cache.db"

        target_path.parent.mkdir(parents=True, exist_ok=True)
        return str(target_path)
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
        self.max_memory_items = max(1, int(max_memory_items)) if max_memory_items is not None else 500
        raw_ttl = os.environ.get("JEVGUARD_CACHE_TTL")
        parsed_ttl: float = 3600.0
        if raw_ttl is not None:
            try:
                parsed_ttl = float(raw_ttl)
            except (ValueError, TypeError):
                parsed_ttl = 3600.0
        elif ttl_seconds is not None:
            try:
                parsed_ttl = float(ttl_seconds)
            except (ValueError, TypeError):
                parsed_ttl = 3600.0
        if math.isnan(parsed_ttl) or math.isinf(parsed_ttl):
            parsed_ttl = 3600.0
        self.ttl_seconds = max(0.0, parsed_ttl)

        self.default_ignore_keys = (
            set(DEFAULT_VOLATILE_KEYS).union({str(k).strip().lower().replace("-", "_") for k in default_ignore_keys})
            if default_ignore_keys is not None
            else set(DEFAULT_VOLATILE_KEYS)
        )
        self._memory_lru: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._local = threading.local()
        self._shared_conn: Optional[sqlite3.Connection] = None
        self._open_conns: Set[sqlite3.Connection] = set()
        self._all_conns: Set[sqlite3.Connection] = set()

        self.stats = {
            "hits": 0,
            "misses": 0,
            "tokens_saved": 0,
        }

        try:
            if self.db_path == ":memory:":
                self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False, timeout=60.0)
                self._shared_conn.row_factory = sqlite3.Row
                self._all_conns.add(self._shared_conn)
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
                self._all_conns.add(self._shared_conn)
            try:
                self._init_db()
            except Exception as err:
                logger.error("Failed to initialize in-memory SQLite fallback: %s", err)

    @contextlib.contextmanager
    def _get_connection(self):
        if self.db_path == ":memory:":
            with self._lock:
                if self._shared_conn is None:
                    self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False, timeout=60.0)
                    self._shared_conn.row_factory = sqlite3.Row
                    self._all_conns.add(self._shared_conn)
                yield self._shared_conn
            return

        conn = getattr(self._local, "conn", None)
        if conn is None:
            try:
                conn = sqlite3.connect(self.db_path, timeout=60.0)
                conn.row_factory = sqlite3.Row
                try:
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA synchronous=NORMAL;")
                    conn.execute("PRAGMA busy_timeout = 60000;")
                except sqlite3.OperationalError:
                    pass
                self._local.conn = conn
                with self._lock:
                    self._open_conns.add(conn)
                    self._all_conns.add(conn)
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
                    hit_count INTEGER NOT NULL DEFAULT 0,
                    tokens_estimate INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_evaluation_cache_created
                ON evaluation_cache(created_at);
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
                for key, value in sorted(data.items(), key=lambda x: str(x[0])):
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
        endpoint: Optional[str] = None,
        tenant_id: Optional[str] = None,
        runtime_version: str = "1.1.0",
        api_key_identity: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        if tenant_id is None and api_key_identity is not None:
            tenant_id = api_key_identity
        # Flexible positional signature backwards compatibility
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
            "endpoint": str(endpoint or "").strip().lower(),
            "model": str(target_model).strip().lower(),
            "questions": target_questions,
            "runtime_version": str(runtime_version).strip(),
            "state": filtered_state,
            "tenant_id": str(tenant_id or "").strip(),
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
            if self.ttl_seconds <= 0:
                return None
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
                    return copy.deepcopy(item["data"])

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
                        try:
                            data = json.loads(row["response_json"])
                        except Exception:
                            conn.execute("DELETE FROM evaluation_cache WHERE fingerprint = ?", (fingerprint,))
                            conn.commit()
                            return None

                        tokens = row["tokens_estimate"]
                        with self._lock:
                            self.stats["hits"] += 1
                            self.stats["tokens_saved"] += tokens
                            self._promote_lru(fingerprint, data, tokens, created_at=entry_created_at)
                        return copy.deepcopy(data)
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
        if self.ttl_seconds <= 0:
            return

        now = time.time()
        data_to_store = copy.deepcopy(response_data)
        try:
            raw_json = json.dumps(data_to_store, separators=(",", ":"), default=str)
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
                if self.ttl_seconds > 0:
                    conn.execute("DELETE FROM evaluation_cache WHERE created_at < ?", (now - self.ttl_seconds,))
                conn.commit()

            with self._lock:
                if self.ttl_seconds > 0:
                    expired_keys = [k for k, v in self._memory_lru.items() if (now - v.get("created_at", 0.0)) > self.ttl_seconds]
                    for k in expired_keys:
                        del self._memory_lru[k]
                self._promote_lru(fingerprint, data_to_store, input_tokens_estimate, created_at=now)
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as err:
            logger.warning("Cache put database error for %s: %s. Falling back to :memory:.", fingerprint, err)
            self._fallback_to_memory()
            with self._lock:
                self._promote_lru(fingerprint, data_to_store, input_tokens_estimate, created_at=now)
        except Exception as err:
            logger.warning("Cache put error for %s: %s", fingerprint, err)
            with self._lock:
                self._promote_lru(fingerprint, data_to_store, input_tokens_estimate, created_at=now)

    def _promote_lru(
        self,
        fingerprint: str,
        data: Dict[str, Any],
        tokens_estimate: int = 0,
        created_at: Optional[float] = None,
    ) -> None:
        if fingerprint in self._memory_lru:
            existing = self._memory_lru.pop(fingerprint)
            hit_count = existing.get("hit_count", 0) + 1
            entry_time = existing.get("created_at", created_at or time.time())
        else:
            hit_count = 0
            entry_time = created_at or time.time()

        while len(self._memory_lru) >= self.max_memory_items:
            if not self._memory_lru:
                break
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
            self.stats = {"hits": 0, "misses": 0, "tokens_saved": 0}
            try:
                with self._get_connection() as conn:
                    conn.execute("DELETE FROM evaluation_cache;")
                    conn.commit()
            except Exception as err:
                logger.warning("Error clearing cache database: %s", err)

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self.stats)

    def close(self) -> None:
        with self._lock:
            self._memory_lru.clear()
            for conn in list(self._all_conns):
                try:
                    conn.close()
                except Exception:
                    pass
            self._all_conns.clear()
            self._open_conns.clear()
            if hasattr(self._local, "conn"):
                self._local.conn = None
            if self._shared_conn is not None:
                try:
                    self._shared_conn.close()
                except Exception:
                    pass
                self._shared_conn = None


class RateLimiter:
    """Thread-safe in-memory rate limiter using a sliding window."""

    def __init__(
        self,
        max_requests: int = 120,
        window_seconds: float = 60.0,
        max_per_minute: Optional[int] = None,
    ):
        if max_per_minute is not None:
            max_requests = max_per_minute
            window_seconds = 60.0
        self.max_requests = max(1, max_requests)
        self.window_seconds = max(1.0, float(window_seconds))
        self.client_timestamps: Dict[str, List[float]] = {}
        self.timestamps: List[float] = []
        self._lock = threading.Lock()

    def acquire(self, client_id: Optional[str] = None) -> bool:
        with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            if client_id is not None:
                ts_list = self.client_timestamps.setdefault(client_id, [])
                ts_list = [t for t in ts_list if t > cutoff]
                if len(ts_list) >= self.max_requests:
                    self.client_timestamps[client_id] = ts_list
                    return False
                ts_list.append(now)
                self.client_timestamps[client_id] = ts_list
                return True
            else:
                self.timestamps = [t for t in self.timestamps if t > cutoff]
                if len(self.timestamps) >= self.max_requests:
                    return False
                self.timestamps.append(now)
                return True


class ResponseCalibrator:
    """Calibrates choice distributions, score rankings, and continuous probabilities."""

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

    def calibrate(
        self,
        raw_answers: Dict[str, Any],
        expected_questions: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        calibrated: Dict[str, Any] = {}
        ambiguous_questions: List[str] = []

        if not isinstance(raw_answers, dict):
            raw_answers = {}

        # 1. Verify all expected questions exist in raw_answers
        if expected_questions:
            for q_name in expected_questions.keys():
                if q_name not in raw_answers:
                    calibrated[q_name] = {
                        "is_ambiguous": True,
                        "status": "AMBIGUOUS_STATE",
                        "calibration": {
                            "reasons": ["missing_answer", f"missing_answer: {q_name}"],
                            "expected": True,
                        },
                        "raw": None,
                    }
                    ambiguous_questions.append(q_name)

        if not raw_answers:
            all_reasons = ["empty_answers", "empty_answers_payload"]
            for it in calibrated.values():
                if isinstance(it, dict) and "calibration" in it:
                    all_reasons.extend(it["calibration"].get("reasons", []))
            summary = {
                "ambiguous_count": len(ambiguous_questions) or (len(expected_questions) if expected_questions else 1),
                "ambiguous_questions": ambiguous_questions or (list(expected_questions.keys()) if expected_questions else ["unspecified"]),
                "has_ambiguity": True,
                "total_evaluated": len(calibrated),
                "verdict": "AMBIGUOUS_STATE",
                "status": "AMBIGUOUS_STATE",
                "reasons": sorted(list(set(all_reasons))),
            }
            return calibrated, summary

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

            if expected_questions and name in expected_questions:
                exp_spec = expected_questions[name]
                if isinstance(exp_spec, dict):
                    exp_type = str(exp_spec.get("type", "")).strip().lower()
                    if exp_type and q_type != exp_type:
                        item["is_ambiguous"] = True
                        item["status"] = "AMBIGUOUS_STATE"
                        cal_reasons = item.setdefault("calibration", {}).setdefault("reasons", [])
                        if "question_type_mismatch" not in cal_reasons:
                            cal_reasons.append("question_type_mismatch")
                        cal_reasons.append(f"question_type_mismatch: expected {exp_type}, got {q_type}")

            if item.get("is_ambiguous", False) and name not in ambiguous_questions:
                ambiguous_questions.append(name)

            calibrated[name] = item

        all_reasons = []
        for it in calibrated.values():
            if isinstance(it, dict) and "calibration" in it:
                all_reasons.extend(it["calibration"].get("reasons", []))

        summary = {
            "ambiguous_count": len(ambiguous_questions),
            "ambiguous_questions": ambiguous_questions,
            "has_ambiguity": len(ambiguous_questions) > 0,
            "total_evaluated": len(calibrated),
            "verdict": "AMBIGUOUS_STATE" if ambiguous_questions else "CONFIDENT",
            "status": "AMBIGUOUS_STATE" if ambiguous_questions else "CONFIDENT",
            "reasons": sorted(list(set(all_reasons))),
        }

        return calibrated, summary

    def _calibrate_choice(self, item: Dict[str, Any]) -> None:
        reasons: List[str] = []
        raw_choice = item.get("choice")
        if raw_choice is None or not str(raw_choice).strip():
            reasons.append("missing_choice_value")

        probs = item.get("probabilities", {})
        parsed_pairs: List[Tuple[str, float]] = []
        has_invalid = False
        if isinstance(probs, dict):
            for k, v in probs.items():
                try:
                    val = float(v)
                    if math.isnan(val) or math.isinf(val) or val < 0.0 or val > 1.0:
                        has_invalid = True
                    else:
                        parsed_pairs.append((str(k), val))
                except (ValueError, TypeError):
                    has_invalid = True
        else:
            has_invalid = True

        if not parsed_pairs:
            try:
                raw_conf = item.get("confidence", 0.0)
                conf = float(raw_conf)
                if math.isnan(conf) or math.isinf(conf) or conf < 0.0 or conf > 1.0:
                    conf = 0.0
                    has_invalid = True
            except (ValueError, TypeError):
                conf = 0.0
                has_invalid = True

            if has_invalid:
                reasons.append("invalid_probability")
            if conf < self.min_top_prob and "low_confidence" not in reasons:
                reasons.append("low_confidence")

            is_amb = len(reasons) > 0
            item["is_ambiguous"] = is_amb
            item["status"] = "AMBIGUOUS_STATE" if is_amb else "CONFIDENT"
            item["calibration"] = {
                "dispersion_gap": round(conf, 4),
                "reasons": reasons,
                "runner_up_choice": None,
                "runner_up_probability": 0.0,
                "top_choice": raw_choice,
                "top_probability": round(conf, 4),
            }
            return

        # Check sum of probabilities
        prob_sum = sum(p for _, p in parsed_pairs)
        if len(parsed_pairs) >= 1 and abs(prob_sum - 1.0) > 0.05:
            reasons.append("invalid_probability_sum")

        sorted_pairs = sorted(parsed_pairs, key=lambda x: x[1], reverse=True)
        top_k, top_p = sorted_pairs[0]
        runner_k, runner_p = sorted_pairs[1] if len(sorted_pairs) > 1 else (None, 0.0)
        gap = top_p - runner_p

        if has_invalid and "invalid_probability" not in reasons:
            reasons.append("invalid_probability")
        if top_p < self.min_top_prob and "low_confidence" not in reasons:
            reasons.append("low_confidence")
        if len(sorted_pairs) > 1 and gap < self.min_dispersion_gap and "flat_distribution" not in reasons:
            reasons.append("flat_distribution")

        # Confront raw_choice with top_choice
        if raw_choice is not None and top_k is not None:
            if str(raw_choice).strip() != str(top_k).strip():
                reasons.append("choice_probability_mismatch")

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
        raw_score = item.get("score")
        if raw_score is None:
            reasons.append("missing_score_value")

        raw_conf = item.get("confidence")
        if raw_conf is None:
            conf = 0.0
            reasons.append("low_confidence")
        else:
            try:
                conf = float(raw_conf)
                if math.isnan(conf) or math.isinf(conf) or conf < 0.0 or conf > 1.0:
                    conf = 0.0
                    reasons.append("invalid_probability")
            except (ValueError, TypeError):
                conf = 0.0
                reasons.append("invalid_probability")

        probs = item.get("probabilities", {})

        if conf < self.min_top_prob and "low_confidence" not in reasons:
            reasons.append("low_confidence")

        dispersion_gap = conf
        if isinstance(probs, dict) and len(probs) >= 1:
            parsed_probs: List[float] = []
            for v in probs.values():
                try:
                    val = float(v)
                    if math.isnan(val) or math.isinf(val) or val < 0.0 or val > 1.0:
                        if "invalid_probability" not in reasons:
                            reasons.append("invalid_probability")
                    else:
                        parsed_probs.append(val)
                except (ValueError, TypeError):
                    if "invalid_probability" not in reasons:
                        reasons.append("invalid_probability")
            if len(parsed_probs) >= 1:
                prob_sum = sum(parsed_probs)
                if abs(prob_sum - 1.0) > 0.05 and "invalid_probability_sum" not in reasons:
                    reasons.append("invalid_probability_sum")
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
            "score": raw_score,
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

        if math.isnan(prob) or math.isinf(prob) or prob < 0.0 or prob > 1.0:
            item["is_ambiguous"] = True
            item["status"] = "AMBIGUOUS_STATE"
            item["calibration"] = {
                "boundary_distance": 0.0,
                "probability": 0.0,
                "reasons": ["invalid_probability", "invalid_noul_range"],
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
        auto_inject_escapes: Optional[bool] = None,
    ) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
        if not questions:
            raise ValueError("Questions payload cannot be empty.")

        should_inject = self.auto_inject_escapes if auto_inject_escapes is None else bool(auto_inject_escapes)

        wire_questions: Dict[str, Dict[str, Any]] = {}
        injected_escapes: Dict[str, str] = {}

        if isinstance(questions, dict):
            for name, q in questions.items():
                wire_q, injected = self._process_question(name, q, auto_inject_escapes=should_inject)
                wire_questions[name] = wire_q
                if injected:
                    injected_escapes[name] = ESCAPE_OPTION_KEY
        elif isinstance(questions, list):
            for idx, q in enumerate(questions):
                if not isinstance(q, dict):
                    raise ValueError(f"Question at index {idx} must be a dictionary.")
                name = str(q.get("name") or f"q_{idx + 1}").strip()
                if name in wire_questions:
                    raise ValueError(f"Duplicate question name detected in question list: '{name}'")
                wire_q, injected = self._process_question(name, q, auto_inject_escapes=should_inject)
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

        if "type" not in q:
            raise ValueError(f"Question '{name}' definition missing required 'type' field.")
        q_type = str(q.get("type", "")).strip().lower()

        raw_instr = q.get("instructions") if q.get("instructions") is not None else q.get("question")
        if isinstance(raw_instr, (dict, list)):
            instructions = raw_instr
        else:
            instructions = str(raw_instr or "").strip()

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
            if not criteria or not isinstance(criteria, list) or len(criteria) == 0:
                raise ValueError(f"Score question '{name}' must define at least one rubric criterion in 'criteria'.")
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

            criteria = {}
            for k, v in raw_crit.items():
                key_str = str(k).strip()
                if isinstance(v, (dict, list)):
                    criteria[key_str] = v
                else:
                    criteria[key_str] = str(v)

            closed = _sanitize_bool(q.get("closed_world", False), "closed_world")
            allow_esc_opt = q.get("auto_inject_escape")
            if allow_esc_opt is None:
                allow_esc_opt = q.get("auto_inject_escapes")
            allow_escape = _sanitize_bool(allow_esc_opt, "auto_inject_escape") if allow_esc_opt is not None else (not closed)
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
        collapse_whitespace: bool = True,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        target_model = (model or self.default_model).strip() or self.default_model
        pruned_state = StatePruner.prune(state, collapse_whitespace=collapse_whitespace)

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
            "injected_escapes": injected_escapes,
            "question_count": len(wire_questions),
        }

        return wire_payload, metadata


class ToolRegistry:
    """Registry maintaining tool schemas and operational handlers."""

    def __init__(self, cache_db_path: Optional[str] = None, allow_test_mocks: Optional[bool] = None):
        self._lock = threading.RLock()
        self.cache = DeterministicCache(db_path=cache_db_path)
        self.optimizer = QuestionOptimizer()
        self.calibrator = ResponseCalibrator()
        self.rate_limiter = RateLimiter(max_requests=120, window_seconds=60.0)

        if allow_test_mocks is not None:
            self.allow_test_mocks = bool(allow_test_mocks)
        else:
            self.allow_test_mocks = (os.environ.get("JEVGUARD_TEST_MODE") == "1")

    def close(self) -> None:
        """Closes underlying cache connections and resources."""
        with self._lock:
            if hasattr(self, "cache") and self.cache is not None:
                self.cache.close()

    def get_definitions(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
            {
                "name": "jevguard_evaluate",
                "description": (
                    "Executes the full deterministic multi-criteria JevGuard pipeline on an arbitrary state "
                    "object against structured question definitions (noul, score, choice). Use this low-level "
                    "tool ONLY for complex, multi-criteria evaluations with custom question dictionaries "
                    "against the upstream TypeSafe AI engine. Do NOT use for simple command checks, code "
                    "patch reviews, or single-choice decisions (use the dedicated jevguard_* tools instead)."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "state": {
                            "type": ["object", "string", "array"],
                            "description": "Input state payload dictionary or structure to evaluate against criteria.",
                        },
                        "questions": {
                            "type": ["object", "array"],
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
                            "description": "HTTP request timeout in seconds (default: 30.0, max: 60.0).",
                            "default": 30.0,
                        },
                        "ignore_keys": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of additional volatile state keys to mask during fingerprinting.",
                        },
                    },
                    "required": ["state", "questions"],
                },
            },
            {
                "name": "jevguard_calibrate",
                "description": (
                    "Performs offline statistical certainty calibration on a pre-computed dictionary of answer "
                    "probabilities without network calls. Use this tool ONLY to detect low confidence "
                    "(top_prob < 0.40) or flat dispersion gaps (< 0.15) on already-evaluated probability outputs. "
                    "Do NOT use for evaluating raw state, running commands, or making decisions."
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
                    "Sanitizes and prunes an arbitrary JSON state payload offline by removing null values, "
                    "empty collections, and collapsing redundant whitespace while safeguarding against circular "
                    "references. Use this utility tool ONLY for cleaning and minimizing state payloads prior "
                    "to transmission or hashing. Do NOT use for evaluating safety or calibrating probabilities."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "state": {
                            "type": ["object", "string", "array"],
                            "description": "The state payload dictionary, list, or structure to sanitize and prune.",
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
                    "Calculates a canonical SHA-256 fingerprint for a state and question set offline with "
                    "volatile key masking (e.g. timestamps, trace IDs). Use this tool ONLY to compute or verify "
                    "the exact deterministic cache key for a state. Do NOT use for making decisions."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "state": {
                            "type": ["object", "string", "array"],
                            "description": "The state payload dictionary or structure to fingerprint.",
                        },
                        "questions": {
                            "type": ["object", "array"],
                            "description": "Optional questions dictionary to bind to the fingerprint.",
                        },
                        "model": {
                            "type": "string",
                            "description": "Target model identifier (default: jev-latest).",
                            "default": "jev-latest",
                        },
                        "auto_inject_escapes": {
                            "type": "boolean",
                            "description": "Whether escape option normalization is applied before hashing.",
                            "default": True,
                        },
                        "ignore_keys": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of additional volatile state keys to mask during fingerprinting.",
                        },
                        "collapse_whitespace": {
                            "type": "boolean",
                            "description": "Whether whitespace was collapsed during state pruning.",
                            "default": True,
                        },
                    },
                    "required": ["state"],
                },
            },
            {
                "name": "jevguard_evaluate_command_safety",
                "description": (
                    "Evaluates the safety and blast radius of a terminal shell command (bash, sh, powershell, cmd) "
                    "before execution. Use this tool ONLY to evaluate shell command strings for destructive actions, "
                    "privilege risks, and autonomous execution safety. Do NOT use for evaluating code diffs, "
                    "architectural decisions, or general probability calibrations. Returns an execution policy: "
                    "ALLOW_AUTONOMOUS, REQUIRE_HUMAN_APPROVAL, or DENY_DESTRUCTIVE."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The shell or terminal command to evaluate for destructive potential.",
                        },
                        "working_dir": {
                            "type": "string",
                            "description": "Target working directory where the command would execute.",
                            "default": "",
                        },
                        "elevated_privileges": {
                            "type": "boolean",
                            "description": "Whether the command runs with sudo or administrator privileges.",
                            "default": False,
                        },
                        "bypass_cache": {
                            "type": "boolean",
                            "description": "Whether to bypass the local cache and force live evaluation.",
                            "default": False,
                        },
                        "timeout": {
                            "type": "number",
                            "description": "Upstream evaluation timeout in seconds (0.1 to 300.0).",
                            "default": 10.0,
                        },
                    },
                    "required": ["command"],
                },
            },
            {
                "name": "jevguard_verify_code_patch",
                "description": (
                    "Verifies a unified git diff or code patch before applying it to a file. Use this tool ONLY "
                    "to inspect code modifications, patches, or diffs for regressions, syntax errors, and security "
                    "vulnerabilities under a specified risk tolerance. Do NOT use for terminal command execution "
                    "or general decisions. Returns approved boolean and recommendation (APPROVE, REQUEST_CHANGES, REJECT)."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "patch_content": {
                            "type": "string",
                            "description": "Unified git diff or source patch text to inspect.",
                        },
                        "target_file": {
                            "type": "string",
                            "description": "Path to the target source file being modified by the patch.",
                        },
                        "risk_tolerance": {
                            "type": "string",
                            "enum": ["strict", "balanced", "permissive"],
                            "description": "Risk tolerance threshold for verification approval.",
                            "default": "balanced",
                        },
                        "bypass_cache": {
                            "type": "boolean",
                            "description": "Whether to bypass the local cache and force live evaluation.",
                            "default": False,
                        },
                        "timeout": {
                            "type": "number",
                            "description": "Upstream evaluation timeout in seconds (0.1 to 300.0).",
                            "default": 10.0,
                        },
                    },
                    "required": ["patch_content", "target_file"],
                },
            },
            {
                "name": "jevguard_evaluate_decision",
                "description": (
                    "Selects the most suitable option from a discrete list of candidate choices (e.g. ['A', 'B', 'C']) "
                    "given contextual background. Use this tool ONLY when choosing between specific named options "
                    "or resolving high-level architectural decisions with closed-world escape fallback. Do NOT use "
                    "for terminal commands, code diffs, or raw multi-criteria state evaluations. Returns the selected "
                    "option, confidence score, and ambiguity status."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "context": {
                            "type": "string",
                            "description": "Background context and constraints informing the decision.",
                        },
                        "decision_question": {
                            "type": "string",
                            "description": "Core decision question to evaluate.",
                        },
                        "options": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of mutually exclusive candidate options to select from.",
                        },
                        "bypass_cache": {
                            "type": "boolean",
                            "description": "Whether to bypass the local cache and force live evaluation.",
                            "default": False,
                        },
                        "timeout": {
                            "type": "number",
                            "description": "Upstream evaluation timeout in seconds (0.1 to 300.0).",
                            "default": 10.0,
                        },
                    },
                    "required": ["context", "decision_question", "options"],
                },
            },
        ]

    def get_tool_allowed_properties(self, tool_name: str) -> Optional[Set[str]]:
        aliases = {
            "evaluate_command_safety": "jevguard_evaluate_command_safety",
            "verify_code_patch": "jevguard_verify_code_patch",
            "evaluate_decision": "jevguard_evaluate_decision",
        }
        lookup_name = aliases.get(tool_name, tool_name)
        for item in self.get_definitions():
            if item.get("name") == lookup_name:
                schema = item.get("inputSchema", {})
                props = schema.get("properties", {})
                return set(props.keys())
        return None

    def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(arguments, dict):
            raise ValueError(f"Tool arguments must be a dictionary, got {type(arguments).__name__}")

        handler_map = {
            "jevguard_prune_state": self._tool_prune_state,
            "jevguard_cache_fingerprint": self._tool_cache_fingerprint,
            "jevguard_calibrate": self._tool_calibrate,
            "jevguard_evaluate": self._tool_evaluate,
            "jevguard_evaluate_command_safety": self._tool_evaluate_command_safety,
            "jevguard_verify_code_patch": self._tool_verify_code_patch,
            "jevguard_evaluate_decision": self._tool_evaluate_decision,
            "evaluate_command_safety": self._tool_evaluate_command_safety,
            "verify_code_patch": self._tool_verify_code_patch,
            "evaluate_decision": self._tool_evaluate_decision,
        }

        if name not in handler_map:
            raise KeyError(f"Unknown tool: '{name}'")

        if not self.rate_limiter.acquire():
            return {
                "status": "error",
                "success": False,
                "error_type": "RateLimitError",
                "message": "Client rate limit exceeded (120 requests/minute).",
                "verdict": "MANUAL_REVIEW_REQUIRED",
                "fallback_action": "MANUAL_REVIEW_REQUIRED",
            }

        allowed_keys = self.get_tool_allowed_properties(name)
        if allowed_keys is not None:
            is_test = self.allow_test_mocks
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

        # Strictly validate and sanitize argument types
        sanitized_args = self._validate_and_sanitize_arguments(name, arguments)

        handler = handler_map[name]
        try:
            # Execute handler without holding registry lock, preventing network deadlocks
            return handler(sanitized_args)
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

    def _validate_and_sanitize_arguments(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(arguments)

        bool_fields = {
            "prune_lists", "auto_inject_escapes", "bypass_cache",
            "collapse_whitespace", "elevated_privileges", "auto_inject_escape"
        }
        for bf in bool_fields:
            if bf in sanitized:
                sanitized[bf] = self._sanitize_bool(sanitized[bf], bf)

        if "timeout" in sanitized:
            sanitized["timeout"] = self._sanitize_float(sanitized["timeout"], "timeout", min_val=0.1, max_val=300.0)
        if "min_top_prob" in sanitized:
            sanitized["min_top_prob"] = self._sanitize_float(sanitized["min_top_prob"], "min_top_prob", min_val=0.0, max_val=1.0)
        if "min_dispersion_gap" in sanitized:
            sanitized["min_dispersion_gap"] = self._sanitize_float(sanitized["min_dispersion_gap"], "min_dispersion_gap", min_val=0.0, max_val=1.0)
        if "noul_uncertainty_margin" in sanitized:
            sanitized["noul_uncertainty_margin"] = self._sanitize_float(sanitized["noul_uncertainty_margin"], "noul_uncertainty_margin", min_val=0.0, max_val=0.5)

        if "questions" in sanitized and isinstance(sanitized["questions"], dict):
            clean_questions = {}
            for q_name, q_val in sanitized["questions"].items():
                if isinstance(q_val, dict):
                    q_copy = dict(q_val)
                    for qb in ("closed_world", "auto_inject_escape", "auto_inject_escapes"):
                        if qb in q_copy:
                            q_copy[qb] = self._sanitize_bool(q_copy[qb], f"questions.{q_name}.{qb}")
                    clean_questions[q_name] = q_copy
                else:
                    clean_questions[q_name] = q_val
            sanitized["questions"] = clean_questions

        return sanitized

    _sanitize_bool = staticmethod(_sanitize_bool)

    @staticmethod
    def _sanitize_float(
        val: Any,
        field_name: str,
        min_val: Optional[float] = None,
        max_val: Optional[float] = None,
    ) -> float:
        try:
            f = float(val)
            if math.isnan(f) or math.isinf(f):
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError(f"Invalid numeric value for argument '{field_name}': {val!r}")

        if min_val is not None and f < min_val:
            raise ValueError(f"Argument '{field_name}' must be >= {min_val}, got {f}")
        if max_val is not None and f > max_val:
            raise ValueError(f"Argument '{field_name}' must be <= {max_val}, got {f}")
        return f

    def _tool_prune_state(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if "state" not in arguments:
                raise ValueError("Missing required argument: 'state'")
            state = arguments["state"]
            prune_lists = self._sanitize_bool(arguments.get("prune_lists", False), "prune_lists")

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
            auto_inject = self._sanitize_bool(arguments.get("auto_inject_escapes", True), "auto_inject_escapes")
            ignore_keys = arguments.get("ignore_keys")
            collapse_whitespace = self._sanitize_bool(arguments.get("collapse_whitespace", True), "collapse_whitespace")

            wire_questions = questions
            if isinstance(questions, (dict, list)) and questions:
                try:
                    wire_questions, _ = self.optimizer.normalize_questions(questions, auto_inject_escapes=auto_inject)
                except Exception:
                    wire_questions = questions

            # Prune state identically to evaluate so fingerprint matches live evaluation
            pruned_state = StatePruner.prune(state, collapse_whitespace=collapse_whitespace)

            endpoint = str(os.environ.get("TYPESAFE_ENDPOINT") or os.environ.get("JEVGUARD_ENDPOINT") or "https://api.typesafe.ai/v1/systemone").strip()
            api_key = str(os.environ.get("TYPESAFE_API_KEY", "")).strip()
            tenant_id = hashlib.sha256(api_key.encode()).hexdigest()[:16] if api_key else None

            fp = DeterministicCache.compute_fingerprint(
                model=model,
                state=pruned_state,
                wire_questions=wire_questions if isinstance(wire_questions, dict) else {},
                ignore_keys=ignore_keys,
                endpoint=endpoint,
                tenant_id=tenant_id,
                runtime_version="1.1.0",
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
            answers = arguments["answers"]
            if not isinstance(answers, dict):
                raise ValueError("Argument 'answers' must be a dictionary")

            min_top_prob = self._sanitize_float(arguments.get("min_top_prob", self.calibrator.min_top_prob), "min_top_prob", min_val=0.0, max_val=1.0)
            min_dispersion = self._sanitize_float(arguments.get("min_dispersion_gap", self.calibrator.min_dispersion_gap), "min_dispersion_gap", min_val=0.0, max_val=1.0)
            noul_margin = self._sanitize_float(arguments.get("noul_uncertainty_margin", self.calibrator.noul_margin), "noul_uncertainty_margin", min_val=0.0, max_val=0.5)

            custom_calibrator = ResponseCalibrator(
                min_top_prob=min_top_prob,
                min_dispersion_gap=min_dispersion,
                noul_uncertainty_margin=noul_margin,
            )

            calibrated, summary = custom_calibrator.calibrate(answers)

            return {
                "success": True,
                "answers": calibrated,
                "calibrated_answers": calibrated,
                "calibration_summary": summary,
                "summary": summary,
                "is_ambiguous": summary["has_ambiguity"],
                "status": summary["status"],
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
            auto_inject = self._sanitize_bool(arguments.get("auto_inject_escapes", True), "auto_inject_escapes")
            bypass_cache = self._sanitize_bool(arguments.get("bypass_cache", False), "bypass_cache")
            timeout = max(1.0, min(self._sanitize_float(arguments.get("timeout", 30.0), "timeout"), 60.0))
            ignore_keys = arguments.get("ignore_keys")

            api_key = str(os.environ.get("TYPESAFE_API_KEY", "")).strip()
            endpoint = str(os.environ.get("TYPESAFE_ENDPOINT") or os.environ.get("JEVGUARD_ENDPOINT") or "https://api.typesafe.ai/v1/systemone").strip()

            is_test = self.allow_test_mocks
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

            collapse_whitespace = self._sanitize_bool(arguments.get("collapse_whitespace", True), "collapse_whitespace")
            wire_payload, opt_metadata = self.optimizer.optimize_and_wire(
                state=state,
                questions=questions,
                model=model,
                auto_inject_escapes=auto_inject,
                collapse_whitespace=collapse_whitespace,
            )
            tokens_estimate = opt_metadata["estimated_tokens"]

            tenant_id = hashlib.sha256(api_key.encode()).hexdigest()[:16] if api_key else None
            fingerprint = DeterministicCache.compute_fingerprint(
                model=wire_payload["model"],
                state=wire_payload["state"],
                wire_questions=wire_payload["questions"],
                ignore_keys=ignore_keys,
                endpoint=endpoint,
                tenant_id=tenant_id,
                runtime_version="1.1.0",
            )

            if not bypass_cache:
                cached_data = self.cache.get(fingerprint)
                if cached_data is not None:
                    t1 = time.perf_counter()
                    latency_ms = round((t1 - t0) * 1000, 3)
                    ans_val = cached_data["answers"]
                    return {
                        "answers": ans_val,
                        "calibrated_answers": ans_val,
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
                        "wire_payload": cached_data.get("wire_payload", wire_payload),
                    }

            raw_answers: Dict[str, Any] = {}
            inference_latency_ms = 0.0
            actual_tokens = tokens_estimate

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
                data_obj = dispatch_res.get("data", {})
                raw_answers = data_obj.get("answers", {})
                usage_info = data_obj.get("usage", {})
                if isinstance(usage_info, dict) and "input_tokens" in usage_info:
                    try:
                        actual_tokens = int(usage_info["input_tokens"])
                    except (ValueError, TypeError):
                        actual_tokens = tokens_estimate
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
            calibrated_answers, calib_summary = self.calibrator.calibrate(
                raw_answers,
                expected_questions=wire_payload["questions"],
            )
            t_cal1 = time.perf_counter()
            calib_ms = round((t_cal1 - t_cal0) * 1000, 3)

            is_mock = mock_answers is not None
            source_mode = "mock_evaluation" if is_mock else "live_evaluation"

            # Only cache evaluations with confident, complete results
            if (not is_mock or self.allow_test_mocks) and not calib_summary.get("has_ambiguity", False):
                self.cache.put(
                    fingerprint=fingerprint,
                    model=wire_payload["model"],
                    response_data={
                        "answers": calibrated_answers,
                        "calibration": calib_summary,
                        "wire_payload": wire_payload,
                        "mode": source_mode,
                    },
                    input_tokens_estimate=actual_tokens,
                )

            t_end = time.perf_counter()
            total_latency = round((t_end - t0) * 1000, 3)

            return {
                "answers": calibrated_answers,
                "calibrated_answers": calibrated_answers,
                "cache_fingerprint": fingerprint,
                "cached": False,
                "calibration": calib_summary,
                "optimization": opt_metadata,
                "success": True,
                "telemetry": {
                    "latency_calibration_ms": calib_ms,
                    "latency_inference_ms": inference_latency_ms,
                    "latency_total_ms": total_latency,
                    "mode": source_mode,
                    "tokens_consumed": actual_tokens,
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

            working_dir = str(arguments.get("working_dir", "")).strip()
            elevated = self._sanitize_bool(arguments.get("elevated_privileges", False), "elevated_privileges")
            mock_answers = arguments.get("mock_answers")
            timeout = max(1.0, min(self._sanitize_float(arguments.get("timeout", 30.0), "timeout"), 60.0))
            bypass_cache = self._sanitize_bool(arguments.get("bypass_cache", False), "bypass_cache")

            state = {
                "command": command.strip(),
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
                "collapse_whitespace": False,
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
            top_choice = choice_item.get("calibration", {}).get("top_choice")
            deny_prob = choice_item.get("probabilities", {}).get("DENY_DESTRUCTIVE", 0.0)
            try:
                deny_prob = float(deny_prob)
            except (ValueError, TypeError):
                deny_prob = 0.0

            # Inspect risk_score
            score_item = answers.get("risk_score", {})
            raw_score = score_item.get("score")
            score_level: Optional[int] = None
            if raw_score is not None:
                try:
                    parsed_score = int(raw_score)
                    if 0 <= parsed_score <= 4:
                        score_level = parsed_score
                    else:
                        score_level = 4
                except (ValueError, TypeError):
                    score_str = str(raw_score).lower()
                    if "critical" in score_str:
                        score_level = 4
                    elif "high" in score_str:
                        score_level = 3
                    elif "moderate" in score_str:
                        score_level = 2
                    elif "low" in score_str:
                        score_level = 1
                    elif "read-only" in score_str or "harmless" in score_str:
                        score_level = 0
                    else:
                        score_level = 4

            # Policy calculation - strict fail-closed autonomous gate
            can_allow_autonomous = (
                raw_choice == "ALLOW_AUTONOMOUS"
                and top_choice == "ALLOW_AUTONOMOUS"
                and not elevated
                and not has_ambiguity
                and (noul_prob is not None and noul_prob < 0.35)
                and (score_level is not None and score_level in (0, 1))
                and deny_prob < 0.10
            )

            if raw_choice == "DENY_DESTRUCTIVE" or (noul_prob is not None and noul_prob >= 0.70) or score_level == 4:
                policy = "DENY_DESTRUCTIVE"
            elif can_allow_autonomous:
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
                    "top_choice": top_choice,
                    "risk_score_level": score_level,
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

            target_file = str(arguments["target_file"]).strip()
            if not target_file:
                raise ValueError("Argument 'target_file' must be a non-empty string")

            risk_tolerance = str(arguments.get("risk_tolerance", "balanced")).strip().lower()
            if risk_tolerance not in ("strict", "balanced", "permissive"):
                raise ValueError("Argument 'risk_tolerance' must be one of: strict, balanced, permissive")

            mock_answers = arguments.get("mock_answers")
            timeout = max(1.0, min(self._sanitize_float(arguments.get("timeout", 30.0), "timeout"), 60.0))
            bypass_cache = self._sanitize_bool(arguments.get("bypass_cache", True), "bypass_cache")

            state = {
                "patch_content": patch_content,
                "target_file": target_file,
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
                "collapse_whitespace": False,
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
            top_rec = choice_item.get("calibration", {}).get("top_choice")
            reject_prob = choice_item.get("probabilities", {}).get("REJECT", 0.0)
            try:
                reject_prob = float(reject_prob)
            except (ValueError, TypeError):
                reject_prob = 0.0

            # Inspect risk_score
            score_item = answers.get("risk_score", {})
            raw_score = score_item.get("score")
            score_level: Optional[int] = None
            if raw_score is not None:
                try:
                    parsed_score = int(raw_score)
                    if 0 <= parsed_score <= 4:
                        score_level = parsed_score
                    else:
                        score_level = 4
                except (ValueError, TypeError):
                    score_str = str(raw_score).lower()
                    if "critical" in score_str:
                        score_level = 4
                    elif "high" in score_str:
                        score_level = 3
                    elif "moderate" in score_str:
                        score_level = 2
                    elif "low" in score_str:
                        score_level = 1
                    elif "clean" in score_str or "safe" in score_str:
                        score_level = 0
                    else:
                        score_level = 4

            can_approve = (
                not has_ambiguity
                and noul_prob is not None
                and raw_rec == "APPROVE"
                and top_rec == "APPROVE"
                and reject_prob < 0.15
                and (score_level is not None and score_level in (0, 1))
            )
            if risk_tolerance == "strict" and (noul_prob is not None and noul_prob >= 0.20):
                can_approve = False
            elif risk_tolerance == "balanced" and (noul_prob is not None and noul_prob >= 0.40):
                can_approve = False
            elif risk_tolerance == "permissive" and (noul_prob is not None and noul_prob >= 0.60):
                can_approve = False

            if raw_rec == "REJECT" or (noul_prob is not None and noul_prob >= 0.70) or score_level == 4:
                rec = "REJECT"
                approved = False
                risk_level = "CRITICAL" if ((noul_prob and noul_prob >= 0.85) or score_level == 4) else "HIGH"
            elif can_approve:
                rec = "APPROVE"
                approved = True
                risk_level = "LOW"
            else:
                rec = "REQUEST_CHANGES"
                approved = False
                if score_level == 3 or (noul_prob and noul_prob >= 0.50):
                    risk_level = "HIGH"
                elif score_level == 2 or (noul_prob and noul_prob >= 0.30):
                    risk_level = "MEDIUM"
                else:
                    risk_level = "MEDIUM" if score_level == 4 else "LOW"

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
                    "top_choice": top_rec,
                    "risk_score_level": score_level,
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

            is_test = self.allow_test_mocks
            mock_answers = arguments.get("mock_answers") if is_test else None
            timeout = max(1.0, min(self._sanitize_float(arguments.get("timeout", 30.0), "timeout"), 60.0))
            bypass_cache = self._sanitize_bool(arguments.get("bypass_cache", False), "bypass_cache")

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
            decision_ans = answers.get("decision")
            if not decision_ans or not isinstance(decision_ans, dict):
                return {
                    "status": "error",
                    "success": False,
                    "error_type": "EvaluationIncompleteError",
                    "message": "Upstream evaluation did not return an answer for 'decision'",
                    "verdict": "MANUAL_REVIEW_REQUIRED",
                    "fallback_action": "MANUAL_REVIEW_REQUIRED",
                    "decision_question": decision_question,
                    "options": options,
                    "selected_option": None,
                    "is_ambiguous": True,
                    "status": "AMBIGUOUS_STATE",
                }

            selected_choice = decision_ans.get("choice")
            confidence = decision_ans.get("confidence", 0.0)
            is_ambiguous = decision_ans.get("is_ambiguous", False)
            status = decision_ans.get("status", "CONFIDENT")

            is_escape = False
            if selected_choice is not None and str(selected_choice).strip():
                sel_clean = str(selected_choice).strip()
                if sel_clean == ESCAPE_OPTION_KEY:
                    is_escape = True
                    selected_choice = ESCAPE_OPTION_KEY
                elif sel_clean in options:
                    is_escape = False
                    selected_choice = sel_clean
                elif sel_clean.lower() in ESCAPE_CANDIDATE_KEYS:
                    is_escape = True
                    selected_choice = ESCAPE_OPTION_KEY
                else:
                    is_ambiguous = True
                    status = "AMBIGUOUS_STATE"
                    reasons = decision_ans.setdefault("calibration", {}).setdefault("reasons", [])
                    reasons.append("unrecognized_selected_option")
            else:
                is_ambiguous = True
                status = "AMBIGUOUS_STATE"
                selected_choice = None

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
        canonical_endpoint = endpoint.strip()
        if not is_authorized_endpoint(canonical_endpoint):
            raise PermissionError(
                f"Endpoint '{canonical_endpoint}' is not permitted. Only official TypeSafe AI endpoints or JEVGUARD_ALLOWED_ENDPOINTS are authorized."
            )

        raw_bytes = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "JevGuard-MCP/1.1.0",
        }

        MAX_RESPONSE_BYTES = 10 * 1024 * 1024
        attempts = 0
        max_attempts = max(1, max_retries + 1)
        opener = urllib.request.build_opener(NoRedirectHandler())
        total_deadline = time.perf_counter() + timeout

        while attempts < max_attempts:
            attempts += 1
            remaining_time = total_deadline - time.perf_counter()
            if remaining_time <= 0.05:
                raise TimeoutError(f"Total timeout of {timeout}s exceeded attempting to reach TypeSafe AI.")

            attempt_timeout = min(timeout, remaining_time)
            req = urllib.request.Request(canonical_endpoint, data=raw_bytes, headers=headers, method="POST")
            t0 = time.perf_counter()

            try:
                with opener.open(req, timeout=attempt_timeout) as resp:
                    status_code = resp.getcode() if hasattr(resp, "getcode") else 200
                    try:
                        body_bytes = resp.read(MAX_RESPONSE_BYTES + 1)
                        if len(body_bytes) > MAX_RESPONSE_BYTES:
                            raise ValueError(f"Upstream response exceeded {MAX_RESPONSE_BYTES} bytes limit")
                    except TypeError:
                        body_bytes = resp.read()
                    t1 = time.perf_counter()
                    latency_ms = round((t1 - t0) * 1000, 3)
                    body = body_bytes.decode("utf-8", errors="replace")
                    try:
                        data = json.loads(body) if body else {}
                    except json.JSONDecodeError as json_err:
                        raise RuntimeError(f"Invalid JSON response from upstream: {json_err}")
                    return {
                        "data": data,
                        "latency_ms": latency_ms,
                        "status_code": status_code,
                        "success": True,
                    }

            except RuntimeError:
                raise

            except urllib.error.HTTPError as err:
                code = err.code
                try:
                    err_body = err.read(65536).decode("utf-8", errors="replace")
                except Exception:
                    err_body = str(err)
                if code in (400, 401, 403, 404, 422):
                    raise RuntimeError(f"HTTP {code} error from TypeSafe AI: {err_body}")

                if code in (429, 500, 502, 503, 504) and attempts < max_attempts:
                    delay = initial_backoff * (2 ** (attempts - 1)) + random.uniform(0.05, 0.25)
                    if time.perf_counter() + delay < total_deadline:
                        time.sleep(delay)
                        continue
                raise RuntimeError(f"HTTP {code} failure: {err_body}")

            except (socket.timeout, TimeoutError) as err:
                if attempts < max_attempts:
                    delay = initial_backoff * (2 ** (attempts - 1)) + random.uniform(0.05, 0.25)
                    if time.perf_counter() + delay < total_deadline:
                        time.sleep(delay)
                        continue
                raise RuntimeError(f"Connection timeout to {endpoint}: {err}")

            except Exception as err:
                if "HTTP redirect" in str(err) or isinstance(err, (ValueError, json.JSONDecodeError)):
                    raise RuntimeError(f"Request error: {err}")
                if attempts < max_attempts:
                    delay = initial_backoff * (2 ** (attempts - 1)) + random.uniform(0.05, 0.25)
                    if time.perf_counter() + delay < total_deadline:
                        time.sleep(delay)
                        continue
                raise RuntimeError(f"Network error connecting to TypeSafe AI: {err}")

        raise RuntimeError("Failed to reach TypeSafe AI after maximum retry attempts")
