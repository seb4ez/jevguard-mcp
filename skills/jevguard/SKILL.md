---
name: jevguard
description: >-
  Deterministic evaluation, safety verification, and certainty calibration for AI agents.
  Use when evaluating terminal command safety, verifying code diffs for regressions,
  making architectural decisions, or routing structured state without closed-world traps.
---

# JevGuard Autonomous Guardrail Skill

JevGuard provides deterministic evaluation, certainty calibration, and safety boundaries for autonomous AI agents. It protects against closed-world hallucinations, ambiguous coin-flip classifications, and destructive terminal operations.

Operates via the local Python runtime (`jevguard`) or the Model Context Protocol server (`jevguard-mcp`).

---

## 1. Pre-Execution Terminal Command Safety

Before executing destructive, state-mutating, or administrative shell commands (`rm`, `dd`, `mkfs`, `systemctl`, `kill`, `pip install`, `git reset`), invoke `evaluate_command_safety`:

### Protocol Call
Call the MCP tool `evaluate_command_safety`:
- `command`: The terminal command string.
- `working_dir`: Execution directory path.
- `elevated_privileges`: True if running with sudo or administrative rights.

### Decision Rules
- `policy == "ALLOW_AUTONOMOUS"`: Execute the command directly.
- `policy == "REQUIRE_HUMAN_APPROVAL"`: Stop and present the risk score and blast radius to the user before proceeding.
- `policy == "DENY_DESTRUCTIVE"`: Refuse autonomous execution immediately and warn the user.
- `status == "error"`: Fall back to `REQUIRE_HUMAN_APPROVAL` defensively.

---

## 2. Code Patch & Diff Verification

Before applying substantial diffs or refactors to critical files (security, authentication, concurrency, database schema), invoke `verify_code_patch`:

### Protocol Call
Call the MCP tool `verify_code_patch`:
- `patch_content`: Unified git diff string.
- `target_file`: Path of the modified file.
- `risk_tolerance`: `"strict"` for production/auth code, `"balanced"` for standard features, `"permissive"` for documentation/tests.

### Decision Rules
- `approved == true`: Apply the patch.
- `approved == false` (`recommendation == "REQUEST_CHANGES"` or `"REJECT"`): Review regression probability and ambiguity reasons. Revise the patch before writing to disk.

---

## 3. Architectural Decision Calibration

When pair-programming or deciding between multiple technical approaches, database engines, or API patterns, invoke `evaluate_decision`:

### Protocol Call
Call the MCP tool `evaluate_decision`:
- `context`: Operational constraints, traffic expectations, and environment limitations.
- `decision_question`: Specific choice to evaluate.
- `options`: List of candidate strings (e.g. `["PostgreSQL", "SQLite", "DuckDB"]`).

### Decision Rules
- JevGuard automatically injects `UNRESOLVED_OR_OTHER` into the option space.
- If `is_escape_selected == true`: None of the proposed options satisfy the requirements. Request additional alternatives or clarify constraints.
- If `status == "AMBIGUOUS_STATE"`: Probability dispersion gap is below 0.15 or confidence is below 0.40. Prompt the user to resolve the trade-off.

---

## 4. Custom State Evaluation & Pipeline Triage

For complex multi-question domain triage, use `jevguard_evaluate` (MCP) or `JevGuardClient` (Python):

```python
from jevguard import JevGuardClient, Noul, Score, Choice

client = JevGuardClient()
res = client.evaluate(
    state={"service": "payment-api", "error_rate": "12.4%"},
    questions={
        "is_outage": Noul(instructions="Does this indicate a service outage?"),
        "severity": Score(instructions="Rate severity", criteria=["Low", "Medium", "High", "Critical"]),
        "route": Choice(instructions="Assign team", criteria={"infra": "Infrastructure", "billing": "Billing Team"})
    }
)

if res.is_ambiguous:
    handle_ambiguous_state(res)
```

---

## 5. Architectural References & Literature Grounding

This skill is designed following formal agentic safety and MCP scaling research:
- **Progressive Disclosure**: Keeps context token overhead under 100 tokens during discovery, loading operational runbooks on demand (TechRxiv 177204917).
- **Stateless MCP Collaboration**: Decoupled stdio JSON-RPC architecture with zero stdout pollution (ArXiv 2601.11595, Google Developers 2026).
- **Defensive Error Sandboxing**: Returns structured payloads (`status: "error"`, `verdict: "MANUAL_REVIEW_REQUIRED"`) preventing protocol teardown (IJCESEN 4872).
- **Canonical SHA-256 Volatile Masking**: Eliminates repeated token costs (0.099 ms cache hit) by masking timestamps and trace IDs.
