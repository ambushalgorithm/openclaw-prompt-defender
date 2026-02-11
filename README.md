# openclaw-prompt-defender

Built with: Kimi K2.5 (via Ollama Cloud) • OpenClaw v2026.2.4

Unified prompt injection detection plugin for OpenClaw — combining the best of `prompt-guard` and `detect-injection` using the **Plugin Gateway Pattern**.

## Overview

This project implements a two-layer security architecture: a thin TypeScript plugin that runs inside OpenClaw's sandbox, and a Python/FastAPI service that runs on the host with full system access. The plugin handles routing and aggregation while the service performs all heavy lifting (pattern matching, vector scanning, 1Password integration).

| Source | Strength | Ported |
|--------|----------|--------|
| **prompt-guard** | Fast pattern matching, 70% token reduction, SHIELD categories, owner bypass | ✅ |
| **detect-injection** | Dual-layer scanning, HF-based vector detection, safety categories | ✅ |

## Architecture — Plugin Gateway Pattern

The plugin doesn't do the work — it **delegates to services** that do.

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────────────┐
│   Discord   │────▶│  Plugin (thin)   │────▶│  HTTP Service Layer     │
│   Message   │     │  - routing logic │     │  (Python/FastAPI)       │
└─────────────┘     │  - simple filters│     │                         │
                    │  - aggregate     │     │  ┌────────────────────┐ │
                    │    results       │     │  │ prompt-guard CLI   │ │
                    └──────────────────┘     │  │ detect-injection   │ │
                             │               │  │ 1Password CLI      │ │
                             ▼               │  │ future tools...    │ │
                       {cancel} or {content} │  └────────────────────┘ │
                                             └─────────────────────────┘
```

**Why this pattern:**
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
│   │   ├── index.ts            # Entry point, manifest export
│   │   ├── handler.ts          # message:received hook handler
│   │   └── services/
│   │       └── security.ts     # HTTP client for security-service
│   ├── openclaw.plugin.json    # Plugin manifest + config schema
│   ├── package.json
│   └── tsconfig.json
│
├── service/                     # Python/FastAPI service (runs on host)
│   ├── app.py                  # FastAPI app, main entry
│   ├── requirements.txt        # fastapi, uvicorn, etc.
│   ├── src/
│   │   ├── scanners/
│   │   │   ├── pattern.py      # prompt-guard pattern matching
│   │   │   └── vector.py       # HF-based vector detection
│   │   ├── integrations/
│   │   │   └── onepassword.py  # 1Password CLI wrapper
│   │   └── models.py           # Pydantic models
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
          "scan_output": false
        }
      }
    }
  }
}
```

**Key differences from skills:**
| Aspect | Skills | Plugins |
|--------|--------|---------|
| Config key | `skills.load.extraDirs` | `plugins.load` |
| Path type | Parent directory (scanned) | Direct plugin directory |
| Discovery | `SKILL.md` | `openclaw.plugin.json` |
| Manifest | `SKILL.md` | `openclaw.plugin.json` |
| Entry point | tools defined | hooks defined |

## Plugin Manifest (`openclaw.plugin.json`)

```json
{
  "name": "openclaw-prompt-defender",
  "version": "0.1.0",
  "description": "Unified prompt injection detection using gateway pattern",
  "entry": "dist/index.js",
  "hooks": {
    "message:received": {
      "description": "Scan incoming messages for prompt injection"
    }
  },
  "configSchema": {
    "type": "object",
    "properties": {
      "service_url": { "type": "string", "default": "http://127.0.0.1:8080" },
      "timeout_ms": { "type": "number", "default": 5000 },
      "fail_open": { "type": "boolean", "default": true },
      "owner_ids": { "type": "array", "items": { "type": "string" } },
      "scan_input": { "type": "boolean", "default": true },
      "scan_output": { "type": "boolean", "default": false }
    },
    "required": ["service_url"]
  }
}
```

## Project Plan

### Phase 1: Foundation (Week 1)
- [ ] Set up project structure (plugin/ + service/)
- [ ] Create OpenClaw plugin manifest
- [ ] Port `prompt-guard` pattern engine to Python service
- [ ] Port `detect-injection` vector scanner to Python service
- [ ] Implement unified service configuration

### Phase 2: Integration (Week 2)
- [ ] Build TypeScript plugin with HTTP client
- [ ] Implement `message:received` hook handler
- [ ] Add owner bypass system (by user ID)
- [ ] Port SHIELD categories to service
- [ ] Create unified severity scoring

### Phase 3: Features (Week 3)
- [ ] Add 1Password CLI integration for secrets
- [ ] Implement fail-open strategy with timeout handling
- [ ] Add service health check endpoint
- [ ] Port hash cache for 90% token reduction
- [ ] Add audit logging integration with openclaw-cmdlog

### Phase 4: Polish (Week 4)
- [ ] Comprehensive test suite (plugin + service)
- [ ] Documentation and deployment guide
- [ ] Performance benchmarking
- [ ] Create setup script for new OpenClaw instances
- [ ] GitHub Actions CI/CD

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
| Service unreachable | Allow message, log warning |
| Timeout exceeded | Allow message, log warning |
| Service returns error | Allow message, log error |
| Scan completes | Follow scan result (allow/block) |

This prevents the security filter from blocking all messages if the service fails.

## Roadmap

- **v0.1.0** — Core gateway pattern, pattern matching, owner bypass
- **v0.2.0** — Vector scanning, 1Password integration, hash cache
- **v0.3.0** — Multi-language support, admin dashboard, metrics
- **v1.0.0** — Stable release, full test coverage, documentation

## License

Dual-licensed under MIT and Apache 2.0 (to match source projects).

---

*Project created: 2026-02-11*  
*Architecture: Plugin Gateway Pattern*  
*Status: Phase 1 - Foundation*
