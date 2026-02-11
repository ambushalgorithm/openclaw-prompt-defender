# openclaw-prompt-defender

Built with: Kimi K2.5 (via Ollama Cloud) • OpenClaw v2026.2.4

Unified prompt injection detection plugin for OpenClaw — combining the best of `prompt-guard` and `detect-injection` using the **Plugin Gateway Pattern**.

**Key capability:** Bidirectional filtering — both user input AND tool output are scanned before reaching the model.

See [docs/DESIGN.md](docs/DESIGN.md) for full architecture, design decisions, and implementation plan.

## Overview

This project implements a two-layer security architecture: a thin TypeScript plugin that runs inside OpenClaw's sandbox, and a Python/FastAPI service that runs on the host with full system access. The plugin handles routing and aggregation while the service performs all heavy lifting (pattern matching, vector scanning, 1Password integration).

| Source | Strength | Ported |
|--------|----------|--------|
| **prompt-guard** | Fast pattern matching, 70% token reduction, SHIELD categories, owner bypass | ✅ |
| **detect-injection** | Dual-layer scanning, HF-based vector detection, safety categories | ✅ |

## Architecture

Two-layer security filtering via **Plugin Gateway Pattern**:
- **Plugin** (TypeScript, sandboxed) — hooks into OpenClaw, delegates to service via HTTP
- **Service** (Python/FastAPI, host) — runs prompt-guard, detect-injection, 1Password CLI

Both user input (`message:received` hook) and tool output (`tool_result:persist` hook) flow through unified `/scan` endpoint with profile-based filtering before reaching the model.

See [docs/DESIGN.md](docs/DESIGN.md) for full architecture diagram, data flow, and design decisions.

## Project Structure

```
openclaw-prompt-defender/
├── docs/
│   └── DESIGN.md           # Architecture & design decisions
├── plugin/                 # TypeScript plugin (runs in OpenClaw sandbox)
│   ├── src/
│   ├── openclaw.plugin.json
│   └── package.json
├── service/                # Python/FastAPI service (runs on host)
│   ├── app.py
│   └── requirements.txt
├── config/
│   └── example.openclaw.json
└── README.md
```

## Quick Start

```bash
# 1. Install service dependencies
cd ~/Projects/openclaw-prompt-defender/service
pip install -r requirements.txt

# 2. Start the service (Terminal 1)
python app.py
# → Service running on http://127.0.0.1:8080

# 3. Build and install plugin (Terminal 2)
cd ~/Projects/openclaw-prompt-defender/plugin
npm install && npm run build

# 4. Configure OpenClaw (see example below)
# Add plugin config to ~/.openclaw/openclaw.json

# 5. Restart OpenClaw
openclaw gateway restart
```

## OpenClaw Configuration

```json
{
  "plugins": {
    "load": {
      "prompt-defender": {
        "package": "~/Projects/openclaw-prompt-defender/plugin",
        "config": {
          "service_url": "http://127.0.0.1:8080",
          "timeout_ms": 5000,
          "fail_open": true,
          "owner_ids": ["1461460866850357345"],
          "scan_input": true,
          "scan_output": true
        }
      }
    }
  }
}
```

## Plugin Manifest (`openclaw.plugin.json`)

```json
{
  "name": "openclaw-prompt-defender",
  "version": "0.1.0",
  "description": "Unified prompt injection and content safety filtering",
  "entry": "dist/index.js",
  "hooks": {
    "message:received": {
      "description": "Scan user messages for prompt injection and jailbreak"
    },
    "tool_result:persist": {
      "description": "Sanitize tool output before model context"
    }
  },
  "configSchema": {
    "type": "object",
    "properties": {
      "service_url": {
        "type": "string",
        "default": "http://127.0.0.1:8080"
      },
      "timeout_ms": {
        "type": "number",
        "default": 5000
      },
      "fail_open": {
        "type": "boolean",
        "default": true,
        "description": "Allow on service failure"
      },
      "owner_ids": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Trusted user IDs (bypass scanning)"
      },
      "scan_input": {
        "type": "boolean",
        "default": true,
        "description": "Enable message_received scanning"
      },
      "scan_output": {
        "type": "boolean",
        "default": true,
        "description": "Enable tool_result_persist scanning"
      }
    },
    "required": ["service_url"]
  }
}
```

## Filter Profiles

| Profile | Type | Checks | Action |
|---------|------|--------|--------|
| **Input (strict)** | `input` | Injection, jailbreak, obfuscation, SHIELD | Block or allow |
| **Output (moderate)** | `output` | PII scrub, content safety, size limit | Sanitize or allow |

Both profiles use the same unified `/scan` endpoint — the service applies the appropriate profile based on `type` parameter.

## Error Handling — Fail Open

By default, the plugin uses **fail-open** strategy: if the security service is unreachable, times out, or errors, the plugin allows/sanitizes minimally and logs a warning. This prevents the security filter outage from blocking all agent functionality.

## Source Projects

| Project | Location | License | Notes |
|---------|----------|---------|-------|
| prompt-guard (fork) | `~/Projects/openclaw-skills/prompt-guard` | MIT | Owner bypass added |
| detect-injection (fork) | `~/Projects/openclaw-skills/detect-injection` | Apache 2.0 | Owner bypass added |
| original prompt-guard | `seojoonkim/prompt-guard` | MIT | Upstream |
| original detect-injection | `protectai/detect-injection` | Apache 2.0 | Upstream |

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/DESIGN.md](docs/DESIGN.md) | Architecture, design decisions, implementation phases, risks |
| This README | Quick start, configuration reference, overview |

## Roadmap

- **v0.1.0** — Core gateway pattern, bidirectional filtering, owner bypass
- **v0.2.0** — Vector scanning, 1Password integration, hash cache
- **v0.3.0** — Multi-language support, admin dashboard, metrics
- **v1.0.0** — Stable release, full test coverage, documentation

See [docs/DESIGN.md](docs/DESIGN.md) for detailed implementation phases.

## License

Dual-licensed under MIT and Apache 2.0 (to match source projects).

---

*Project created: 2026-02-11*  
*Repository: https://github.com/crayon-doing-petri/openclaw-prompt-defender*  
*Status: Phase 1 - Foundation*
