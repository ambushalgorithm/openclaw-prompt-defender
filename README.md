# openclaw-prompt-defender

Built with: Kimi K2.5 (via Ollama Cloud) • OpenClaw v2026.2.4

Unified prompt injection detection plugin for OpenClaw — combining the best of `prompt-guard` and `detect-injection` using the **Plugin Gateway Pattern**.

## Overview

This project implements a two-layer security architecture: a thin TypeScript plugin that runs inside OpenClaw's sandbox, and a Python/FastAPI service that runs on the host with full system access. The plugin handles routing and aggregation while the service performs all heavy lifting (pattern matching, vector scanning, 1Password integration).

**Key capability:** Bidirectional filtering — both user input AND tool output are scanned before reaching the model.

| Source | Strength | Ported |
|--------|----------|--------|
| **prompt-guard** | Fast pattern matching, 70% token reduction, SHIELD categories, owner bypass | ✅ |
| **detect-injection** | Dual-layer scanning, HF-based vector detection, safety categories | ✅ |

## Architecture — Plugin Gateway Pattern

The plugin doesn't do the work — it **delegates to services** that do.

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           OpenClaw Gateway                               │
│                                                                          │
│  USER INPUT FLOW:                                                        │
│  ┌──────────────┐     ┌─────────────┐     ┌──────────────────────┐      │
│  │  User Msg    │────▶│  message_   │────▶│   Security Service   │      │
│  │  (Discord)   │      │  received   │      │  (Python/FastAPI)    │      │
│  └──────────────┘      │   hook      │      └──────────┬───────────┘      │
│                        └─────────────┘                 │                │
│                                                        ▼                │
│                                               ┌─────────────────┐       │
│                                               │  Unified Scan   │       │
│                                               │  • Injection    │       │
│                                               │  • Jailbreak    │       │
│                                               │  • Owner bypass │       │
│                                               └────────┬────────┘       │
│                                                        │                │
│  TOOL OUTPUT FLOW:                                     ▼                │
│  ┌──────────────┐     ┌─────────────┐         ┌─────────────────┐       │
│  │  web_search  │──┐  │  tool_      │         │  Input Filter   │       │
│  │  file_read   │──┼─▶│  result_    │────────▶│  (strict)       │       │
│  │  API call    │──┘  │  persist    │         └────────┬────────┘       │
│  └──────────────┘     │   hook      │                  │                │
│                       └─────────────┘                  │                │
│                                                        ▼                │
│                                               ┌─────────────────┐       │
│                                               │  Output Filter  │       │
│                                               │  (moderate)     │       │
│                                               │  • PII scrub    │       │
│                                               │  • Safety       │       │
│                                               └────────┬────────┘       │
│                                                        │                │
│                             ┌─────────────────────────┘                │
│                             │                                          │
│                             ▼                                          │
│                    ┌─────────────────────┐                              │
│                    │   Session Context   │                              │
│                    │  (what model reads) │                              │
│                    └──────────┬──────────┘                              │
│                               │                                        │
│                               ▼                                        │
│                      ┌─────────────────┐                               │
│                      │   LLM Model     │                               │
│                      │  receives       │                               │
│                      │  clean data     │                               │
│                      └─────────────────┘                               │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Two Hooks, One Service

| Hook | Triggers | Modifies? | Use Case |
|------|----------|-----------|----------|
| `message:received` | User sends message | ✅ Yes (content, cancel) | Input filtering: injection, jailbreak |
| `tool_result:persist` | Tool result ready | ✅ Yes (message) | Output filtering: PII scrub, content safety |

**Note:** Both hooks call the same `/scan` endpoint — service uses `type=input|output` to apply appropriate profile.

### Why This Pattern

| Aspect | Benefit |
|--------|---------|
| **Language freedom** | Python, Go, Rust — HTTP doesn't care |
| **System access** | Service layer has 1Password CLI, subprocess, file access |
| **Future tools** | Add new service endpoint, no plugin rewrite |
| **Testing** | Services can be tested standalone |
| **Incremental** | Move tools to services as needed |

## Project Structure

```
openclaw-prompt-defender/
├── plugin/                      # TypeScript plugin (runs in OpenClaw sandbox)
│   ├── src/
│   │   ├── index.ts            # Entry point, hooks registration
│   │   ├── handlers/
│   │   │   ├── input.ts        # message:received handler
│   │   │   └── output.ts       # tool_result:persist handler
│   │   └── services/
│   │       └── security.ts     # HTTP client for service
│   ├── openclaw.plugin.json    # Plugin manifest + config schema
│   ├── package.json
│   └── tsconfig.json
│
├── service/                     # Python/FastAPI service (runs on host)
│   ├── app.py                  # FastAPI app, /scan endpoint
│   ├── requirements.txt        # fastapi, uvicorn, etc.
│   ├── src/
│   │   ├── engine.py           # Unified FilterEngine
│   │   ├── scanners/
│   │   │   ├── pattern.py      # prompt-guard pattern matching
│   │   │   └── vector.py       # HF-based vector detection
│   │   ├── profiles.py         # Input/Output profile configs
│   │   └── integrations/
│   │       └── onepassword.py  # 1Password CLI wrapper
│   └── tests/
│
├── config/
│   └── example.openclaw.json   # OpenClaw plugin configuration
│
└── README.md
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

**Key differences from skills:**
| Aspect | Skills | Plugins |
|--------|--------|---------|
| Config key | `skills.load.extraDirs` | `plugins.load` (object, not array) |
| Path type | Parent directory (scanned) | Direct plugin directory |
| Discovery | `SKILL.md` | `openclaw.plugin.json` |
| Manifest | `SKILL.md` | `openclaw.plugin.json` |
| Entry point | Tools defined | Hooks defined |

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

## Service API

### Single Endpoint: `/scan`

Both input and output use the same endpoint with different `type`.

```bash
# User input (strict profile)
POST http://127.0.0.1:8080/scan
Content-Type: application/json

{
  "type": "input",
  "content": "user message here",
  "user_id": "1461460866850357345"
}

# Tool output (moderate profile)
POST http://127.0.0.1:8080/scan
Content-Type: application/json

{
  "type": "output",
  "content": "web search result here",
  "tool_name": "web_search"
}
```

### Response Format

```json
{
  "action": "allow" | "block" | "sanitize",
  "sanitized": "modified content if action=sanitize",
  "severity": "none" | "low" | "medium" | "high" | "critical",
  "reasons": ["injection_detected", "pii_found"],
  "scan_time_ms": 45
}
```

## Project Plan

### Phase 1: Foundation (Week 1)
- [ ] Set up project structure (plugin/ + service/)
- [ ] Create OpenClaw plugin manifest with both hooks
- [ ] Implement `/scan` endpoint with profile switching
- [ ] Port `prompt-guard` pattern engine
- [ ] Port `detect-injection` vector scanner
- [ ] Add owner bypass system

### Phase 2: Integration (Week 2)
- [ ] Build TypeScript plugin with HTTP client
- [ ] Implement `message:received` handler
- [ ] Implement `tool_result:persist` handler
- [ ] Create input profile (strict) — injection, jailbreak
- [ ] Create output profile (moderate) — PII, content safety

### Phase 3: Features (Week 3)
- [ ] Port hash cache for 90% token reduction
- [ ] Add 1Password CLI integration
- [ ] Implement fail-open strategy with timeout handling
- [ ] Add service health check endpoint
- [ ] Add audit logging integration with openclaw-cmdlog

### Phase 4: Polish (Week 4)
- [ ] Comprehensive test suite (plugin + service)
- [ ] Documentation and deployment guide
- [ ] Performance benchmarking
- [ ] Create setup script for new OpenClaw instances
- [ ] GitHub Actions CI/CD

## Hook Verification Status

✅ **All required hooks verified available in current fork**

| Hook | Available In | Modifies Content | Can Cancel |
|------|--------------|------------------|------------|
| `message:received` | `feat/message-received` branch | ✅ Yes | ✅ Yes |
| `tool_result:persist` | Core OpenClaw | ✅ Yes | ❌ No* |

*Note: `tool_result_persist` can modify to empty but can't fully cancel — model sees empty/sanitized result.

**No additional fork changes required** — PR #12637 (already merged) provides `message_received`, and `tool_result_persist` is in core OpenClaw.

## Source Projects

| Project | Location | License | Notes |
|---------|----------|---------|-------|
| prompt-guard (fork) | `~/Projects/openclaw-skills/prompt-guard` | MIT | Owner bypass added |
| detect-injection (fork) | `~/Projects/openclaw-skills/detect-injection` | Apache 2.0 | Owner bypass added |
| original prompt-guard | `seojoonkim/prompt-guard` | MIT | Upstream |
| original detect-injection | `protectai/detect-injection` | Apache 2.0 | Upstream |

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

# 4. Configure OpenClaw
# Add plugin config to ~/.openclaw/openclaw.json

# 5. Restart OpenClaw
openclaw gateway restart
```

## Error Handling — Fail Open

By default, the plugin uses **fail-open** strategy:

| Scenario | Behavior |
|----------|----------|
| Service unreachable | Allow/sanitize minimally, log warning |
| Timeout exceeded | Allow/sanitize minimally, log warning |
| Service returns error | Allow/sanitize minimally, log error |
| Scan completes | Follow scan result (allow/block/sanitize) |

This prevents the security filter from blocking all messages if the service fails.

## Filter Profiles

| Profile | Type | Checks | Action |
|---------|------|--------|--------|
| **Input (strict)** | `input` | Injection, jailbreak, obfuscation, SHIELD | Block or allow |
| **Output (moderate)** | `output` | PII scrub, content safety, size limit | Sanitize or allow |

## Roadmap

- **v0.1.0** — Core gateway pattern, bidirectional filtering, owner bypass
- **v0.2.0** — Vector scanning, 1Password integration, hash cache
- **v0.3.0** — Multi-language support, admin dashboard, metrics
- **v1.0.0** — Stable release, full test coverage, documentation

## License

Dual-licensed under MIT and Apache 2.0 (to match source projects).

---

*Project created: 2026-02-11*  
*Architecture: Plugin Gateway Pattern*  
*Hooks: message:received + tool_result:persist*  
*Status: Phase 1 - Foundation*
