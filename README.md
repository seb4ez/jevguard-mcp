# JevGuard MCP Server

Official Model Context Protocol (MCP) server for JevGuard, the deterministic evaluation and certainty calibration runtime for TypeSafe AI.

This package exposes core JevGuard primitives through JSON-RPC 2.0 over standard input/output (stdio), adhering to the MCP 2024-11-05 specification.

## Architectural Principles

1. Zero External Dependencies: Implemented strictly with the Python standard library (`sys`, `json`, `sqlite3`, `hashlib`, `urllib`).
2. Protocol Fidelity: Full compliance with the MCP 2024-11-05 standard, supporting initialize handshakes, ping, tool discovery, and tool execution.
3. Deterministic Execution: State sanitization, closed-world neutral escape injection, probability dispersion analysis, and SHA-256 fingerprint caching.
4. Process Isolation: Runs as an independent stdio subprocess compatible with Claude Desktop, Cursor IDE, LibreChat, and custom MCP clients.

## Empirical Benchmark (5 Vanilla vs 5 JevGuard MCP)

A live benchmark was conducted directly against the official TypeSafe AI endpoint (`https://api.typesafe.ai/v1/systemone`, model `jev-latest`) comparing 5 vanilla API calls against 5 JevGuard MCP tool calls.

![JevGuard MCP Benchmark](benchmark_results.png)

### Key Empirical Findings

1. Deterministic Cache Speedup (0.099 ms): Repeated queries containing dynamic timestamps and trace IDs are intercepted locally. Volatile key masking matches the canonical SHA-256 fingerprint, resulting in a 7,400x speedup and 0 tokens consumed.
2. Closed-World Trap Mitigation: In Scenario 3 (an off-topic inquiry about corporate tax offices in Zurich), Vanilla TypeSafe AI forced an arbitrary classification (`credit_card_chargeback`). JevGuard MCP automatically injected `UNRESOLVED_OR_OTHER`, safely catching the out-of-distribution input with 100% certainty.
3. Ambiguity Calibration: In Scenario 1, boundary uncertainty on `is_outage` (`noul=0.49`, distance 0.01 to threshold) and flat distribution on `severity` (0.08 gap) were detected and flagged as `AMBIGUOUS_STATE`.
4. Standard Library Overhead: Local middleware execution latency remained below 0.3 ms for cold requests and 0.099 ms for warm cache lookups.

## Available Tools

### 1. `jevguard_evaluate`
Executes the deterministic JevGuard evaluation pipeline:
- Prunes incoming state data to eliminate empty keys and duplicate whitespace.
- Normalizes question schemas and injects closed-world escape alternatives (`UNRESOLVED_OR_OTHER`) to prevent false positives.
- Computes canonical SHA-256 fingerprints with volatile key masking.
- Queries the zero-token cache on hit or dispatches upstream to TypeSafe AI when credentials are configured.
- Calibrates response certainty and dispersion metrics.

### 2. `jevguard_calibrate`
Analyzes response probability distributions to prevent false certainty:
- Flags low confidence when the top probability falls below 0.40 (`top_prob < 0.40`).
- Flags flat distributions when the gap between top and runner-up choices is below 0.15 (`dispersion_gap < 0.15`).
- Evaluates boundary uncertainty for continuous noul probability ranges near 0.50 (`|prob - 0.50| < 0.12`).
- Returns structured verdicts: `AMBIGUOUS_STATE` or `CONFIDENT`.

### 3. `jevguard_prune_state`
Sanitizes structured input states:
- Removes null values and empty strings/collections from mapping objects.
- Normalizes and collapses repeated whitespace.
- Detects circular references and replaces them with `<cyclic_ref>` tokens.
- Calculates an input token count estimate.

### 4. `jevguard_cache_fingerprint`
Calculates a canonical SHA-256 fingerprint:
- Recursively strips volatile fields (`timestamp`, `trace_id`, `request_id`, `created_at`, `updated_at`, `nonce`).
- Orders dictionary keys deterministically.
- Produces identical hashes for semantically identical states regardless of key ordering or volatile timestamp variance.

## Installation

Install the package directly in editable mode or as a standalone module using standard Python:

```bash
cd /path/to/jevguard-mcp
pip install -e .
```

Alternatively, run directly with Python without installing:

```bash
python -m jevguard_mcp.server
```

## Client Configurations

### 1. Claude Desktop

Add the server to your `claude_desktop_config.json`:

- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "jevguard": {
      "command": "python",
      "args": [
        "-m",
        "jevguard_mcp.server"
      ],
      "env": {
        "TYPESAFE_API_KEY": "your_typesafe_api_key_here"
      }
    }
  }
}
```

### 2. Cursor IDE

Add the server in Cursor Settings under Features -> MCP Servers -> Add New MCP Server, or save directly into `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "jevguard": {
      "command": "python",
      "args": [
        "-m",
        "jevguard_mcp.server"
      ],
      "env": {
        "TYPESAFE_API_KEY": "your_typesafe_api_key_here"
      }
    }
  }
}
```

### 3. LibreChat

Add the server to your `librechat.yaml` configuration file:

```yaml
mcpServers:
  jevguard:
    type: stdio
    command: python
    args:
      - "-m"
      - "jevguard_mcp.server"
    env:
      TYPESAFE_API_KEY: "your_typesafe_api_key_here"
```

## Running the Test Suite

Run the unit tests with Python's standard `unittest` runner:

```bash
python -m unittest test_mcp_server.py -v
```

## License

MIT License. Copyright (c) 2026 Seb4Ez.
