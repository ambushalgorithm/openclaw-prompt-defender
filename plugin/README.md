# Prompt Defender Plugin

OpenClaw plugin for scanning tool outputs before they reach the LLM — blocks prompt injection, jailbreaks, and malicious content.

## What It Does

Intercepts tool results via the `before_tool_result` hook and sends them to a security scanning service:

```
Tool executes (exec, read, web_fetch, etc.)
    ↓
Plugin intercepts via before_tool_result hook
    ↓
Sends content to security service (/scan endpoint)
    ↓
Service returns: allow | block | sanitize
    ↓
Plugin enforces verdict before LLM sees content
```

## Requirements

- OpenClaw with `before_tool_result` hook support
- Security service running (see `../service/`)

## Installation

### 1. Build the Plugin

```bash
cd plugin
npm install
npm run build
```

### 2. Configure OpenClaw

Add to `openclaw.json`:

```json
{
  "plugins": {
    "load": [
      {
        "package": "/path/to/openclaw-prompt-defender/plugin",
        "config": {
          "service_url": "http://localhost:8080",
          "timeout_ms": 5000,
          "fail_open": true,
          "scan_enabled": true,
          "features": {
            "prompt_guard": true
          }
        }
      }
    ]
  }
}
```

### 3. Start the Service

```bash
cd ../service
python app.py
# Or: uvicorn app:app --reload --port 8080
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `service_url` | string | `http://localhost:8080` | Security scanning service URL |
| `timeout_ms` | number | `5000` | Request timeout in milliseconds |
| `fail_open` | boolean | `true` | Allow content if service is unavailable |
| `scan_enabled` | boolean | `true` | Enable/disable all scanning |
| `features.prompt_guard` | boolean | `true` | Enable prompt-guard pattern scanning |

## Features

- **Prompt Guard** — 500+ regex patterns for injection/jailbreak detection
- **Fail-Open Safety** — If the service goes down, tool results pass through
- **Owner Bypass** — Trusted users can skip scanning
- **Sanitization** — Remove threats instead of blocking (optional)

## Files

| File | Purpose |
|------|---------|
| `src/index.ts` | Plugin logic (hook registration, service calls) |
| `openclaw.plugin.json` | Plugin manifest & config schema |
| `package.json` | NPM dependencies |
| `tsconfig.json` | TypeScript config |

## Logging

Plugin logs to OpenClaw's logger:
- `[Prompt Defender] Scanning tool result: {toolName}`
- `[Prompt Defender] BLOCKED {toolName}: {count} pattern(s) matched`
- `[Prompt Defender] ALLOWED {toolName}`

See service README for persistent logging.
