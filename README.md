# openclaw-prompt-defender

Built with: Claude Sonnet 4.5 • OpenClaw v2026.2.4 (custom branch with `before_tool_result` hook)

**Prompt injection detection and jailbreak prevention** for OpenClaw — combining the best detection methods from `prompt-guard`, `detect-injection`, and `openclaw-shield` using the **Plugin Gateway Pattern**.

**Current Status:** 🔄 **Phase 3a** - Implementing prompt-guard patterns (500+ regex patterns across 3 tiers)

---

## Overview

A security plugin that scans **tool outputs** before they reach the LLM, preventing:
- Prompt injection attacks
- Jailbreak attempts
- Secret/credential leakage
- PII exposure
- Malicious content injection

**Sequential feature rollout:**
1. ✅ **Phase 1-2**: Core infrastructure (plugin + service + logging)
2. 🔄 **Phase 3a**: prompt-guard implementation (500+ regex patterns)
3. ⏸️ **Phase 3b**: detect-injection (ML-based detection)
4. ⏸️ **Phase 3c**: openclaw-shield (secrets/PII patterns)

Each feature is **independently toggleable** via feature flags.

---

## Architecture

### Plugin Gateway Pattern

```
Tool Output (e.g., web_fetch, exec, read)
    ↓
OpenClaw before_tool_result hook
    ↓
Plugin (TypeScript, sandboxed)
    ↓ HTTP POST /scan
Security Service (Python/FastAPI, host)
    ↓
Tiered Pattern Matching (critical → high → medium)
    ↓
ALLOW / BLOCK / SANITIZE
    ↓
Back to OpenClaw → LLM (if allowed)
```

**Why this design:**
- **Plugin** runs in OpenClaw's sandbox → can't access Python ML libraries
- **Service** runs on host → full access to ML models, pattern libraries, system tools
- **Hook timing** → `before_tool_result` intercepts output before LLM sees it

---

## Detection Methods (Feature Flags)

Each scanner can be enabled/disabled independently:

| Feature | Source | Patterns | Status |
|---------|--------|----------|--------|
| **prompt_guard** | [prompt-guard](https://github.com/seojoonkim/prompt-guard) | 500+ regex (3 tiers) | 🔄 Implementing |
| **ml_detection** | [detect-injection](https://github.com/protectai/detect-injection) | HuggingFace DeBERTa | ⏸️ Phase 3b |
| **secret_scanner** | [openclaw-shield](https://github.com/knostic/openclaw-shield) | Secrets/PII patterns | ⏸️ Phase 3c |
| **content_moderation** | detect-injection | OpenAI API | ⏸️ Phase 3b |

---

## Project Structure

```
openclaw-prompt-defender/
├── docs/
│   └── DESIGN.md           # Architecture, design decisions
│
├── plugin/                 # TypeScript (runs in OpenClaw sandbox)
│   ├── src/
│   │   ├── index.ts        # Main plugin entry (before_tool_result hook)
│   │   └── types/types.d.ts
│   ├── openclaw.plugin.json
│   ├── package.json
│   └── tsconfig.json
│
├── service/                # Python/FastAPI (runs on host)
│   ├── app.py              # FastAPI service (/scan endpoint)
│   ├── logger.py           # Persistent JSONL logging
│   ├── patterns.py         # 🔄 Pattern definitions (YAML → Python)
│   ├── scanner.py          # 🔄 Tiered scanning engine
│   ├── decoder.py          # 🔄 Base64/encoding detection
│   ├── config.py           # 🔄 Configuration management
│   ├── requirements.txt
│   └── Dockerfile          # For end-to-end testing
│
├── TODO.md                 # Current task list
└── README.md               # This file
```

---

## Quick Start (Docker Testing)

### 1. Build and Run Service

```bash
cd ~/Projects/openclaw-plugins/openclaw-prompt-defender/service
docker build -t prompt-defender:latest .
docker run -d \
  -p 8080:8080 \
  -v ~/.openclaw/logs:/root/.openclaw/logs \
  --name prompt-defender \
  prompt-defender:latest
```

### 2. Build and Install Plugin

```bash
cd ~/Projects/openclaw-plugins/openclaw-prompt-defender/plugin
npm install && npm run build

# Link into OpenClaw extensions
mkdir -p ~/.openclaw/extensions
ln -s $(pwd)/dist ~/.openclaw/extensions/prompt-defender
```

### 3. Configure OpenClaw

Edit `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "prompt-defender": {
        "enabled": true,
        "config": {
          "service_url": "http://127.0.0.1:8080",
          "timeout_ms": 5000,
          "fail_open": true,
          
          "owner_ids": ["1461460866850357345"],
          
          "features": {
            "prompt_guard": true,
            "ml_detection": false,
            "secret_scanner": false,
            "content_moderation": false
          },
          
          "prompt_guard": {
            "scan_tier": 1,
            "hash_cache": true,
            "decode_base64": true,
            "multilang": ["en", "ko", "ja", "zh"]
          }
        }
      }
    }
  }
}
```

### 4. Restart OpenClaw

```bash
# Using custom branch with before_tool_result hook
cd ~/Projects/openclaw-development
openclaw gateway restart
```

---

## Configuration Reference

### Top-Level Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `service_url` | string | `http://127.0.0.1:8080` | Security service endpoint |
| `timeout_ms` | number | `5000` | Request timeout |
| `fail_open` | boolean | `true` | Allow on service failure |
| `owner_ids` | array | `[]` | Trusted user IDs (bypass scanning) |

### Feature Flags (`features.*`)

| Flag | Default | Description |
|------|---------|-------------|
| `prompt_guard` | `true` | 500+ regex patterns (3 tiers) |
| `ml_detection` | `false` | HuggingFace ML model (requires `HF_TOKEN`) |
| `secret_scanner` | `false` | Secrets/PII detection |
| `content_moderation` | `false` | OpenAI API moderation (requires `OPENAI_API_KEY`) |

### prompt_guard Config (`prompt_guard.*`)

| Field | Default | Description |
|-------|---------|-------------|
| `scan_tier` | `1` | 0=critical, 1=+high, 2=+medium |
| `hash_cache` | `true` | Skip repeated content (~70% token reduction) |
| `decode_base64` | `true` | Detect Base64/URL encoded attacks |
| `multilang` | `["en"]` | Languages to scan (en, ko, ja, zh, etc.) |

---

## Tiered Scanning (prompt_guard)

Progressive pattern loading for performance:

| Tier | Patterns | Load When | Scan Time |
|------|----------|-----------|-----------|
| **0: Critical** | ~30 | Always | <5ms |
| **1: High** | ~70 | After Tier 0 match OR tier=1+ | <15ms |
| **2: Medium** | ~200+ | After Tier 1 match OR tier=2 | <50ms |

**Result:** ~70% token reduction while maintaining detection accuracy.

---

## Owner Bypass

Trusted users skip all scanning for zero overhead:

```json
{
  "owner_ids": ["1461460866850357345"]
}
```

When a tool output is from an owner's action, the service returns immediate ALLOW without pattern matching.

---

## Logging

All security events are logged to `~/.openclaw/logs/` in JSONL format:

### Log Files

```
~/.openclaw/logs/
├── config-audit.jsonl                     # OpenClaw system logs
├── prompt-defender-threats.jsonl          # Blocked attacks only
├── prompt-defender-scans.jsonl            # All scan events
└── prompt-defender-summary.json           # Daily statistics
```

### Example Log Entries

**Threat** (`prompt-defender-threats.jsonl`):
```json
{"timestamp":"2026-02-14T13:45:32.123456","severity":"high","tool":"web_fetch","patterns":["ignore all previous","disregard your guidelines"],"categories":["instruction_override","jailbreak"],"content_hash":"a1b2c3d4e5f6g7h8"}
```

**Scan** (`prompt-defender-scans.jsonl`):
```json
{"timestamp":"2026-02-14T13:45:32.789012","action":"block","tool_name":"web_fetch","severity":"high","pattern_count":2,"duration_ms":12,"categories":["instruction_override","jailbreak"]}
```

### Statistics API

```bash
curl http://127.0.0.1:8080/stats?hours=24
```

**Response:**
```json
{
  "period_hours": 24,
  "total_scans": 142,
  "total_threats": 3,
  "by_severity": {"high": 2, "medium": 1},
  "by_category": {"instruction_override": 2, "jailbreak": 1},
  "by_tool": {"web_fetch": 2, "exec": 1}
}
```

---

## Pattern Categories (prompt_guard)

### Tier 0: Critical (Always Loaded)

- **data_exfiltration** - Reading config files, env vars, credentials
- **system_destruction** - `rm -rf`, fork bombs
- **sql_injection** - DROP TABLE, TRUNCATE
- **xss** - `<script>`, `javascript:`
- **prompt_extraction** - Requesting system prompts
- **phishing** - Password reset templates
- **mcp_abuse** - Tool exploitation
- **unicode_tag** - Invisible instruction injection

### Tier 1: High (Load After Critical Match)

- **instruction_override** - "Ignore all previous instructions" (10 languages)
- **jailbreak** - DAN mode, "Do Anything Now"
- **system_impersonation** - Fake system/admin messages
- **system_mimicry** - Fake XML/prompt tags
- **token_smuggling** - Zero-width characters
- **system_file_access** - `/etc/passwd`, `.ssh/`
- **scenario_jailbreak** - Story/research bypass
- **hooks_hijacking** - Auto-approve exploitation
- **gitignore_bypass** - Reading `.env` files

### Tier 2: Medium (Deep Scan Mode)

- **role_manipulation** - "You are now...", "Pretend to be..."
- **authority_impersonation** - "I am the admin"
- **context_hijacking** - Session manipulation
- (200+ additional patterns)

---

## API Reference

### POST /scan

**Request:**
```json
{
  "type": "output",
  "tool_name": "web_fetch",
  "content": "Content to scan...",
  "is_error": false,
  "duration_ms": 120,
  "source": "user_id_here"
}
```

**Response:**
```json
{
  "action": "block",
  "reason": "Potential prompt injection detected (2 pattern(s) matched)",
  "matches": [
    {
      "pattern": "ignore all previous",
      "severity": "high",
      "type": "instruction_override",
      "lang": "en"
    }
  ]
}
```

**Actions:**
- `allow` - Pass through to LLM
- `block` - Drop output, return error to user
- `sanitize` - Redact sensitive content, pass sanitized version (future)

### GET /health

**Response:**
```json
{
  "status": "ok",
  "service": "prompt-defender",
  "version": "0.1.0"
}
```

### GET /stats?hours=24

**Response:** See Logging section above.

### GET /patterns

**Response:**
```json
{
  "patterns": ["pattern1", "pattern2", ...],
  "count": 500
}
```

---

## Error Handling

**Fail-Open Strategy:**
- Service unreachable → ALLOW + log warning
- Service timeout → ALLOW + log warning
- Service error → ALLOW + log error

This prevents security filter outages from breaking the agent.

**Override:**
```json
{
  "fail_open": false  // Fail-closed: block on error
}
```

---

## Testing

### Unit Tests
```bash
cd service
pytest tests/
```

### Integration Tests (Docker)
```bash
cd service
docker-compose up --build
docker exec -it prompt-defender pytest tests/integration/
```

### End-to-End Tests
```bash
# Start service in Docker
docker-compose up -d

# Run OpenClaw with test suite
cd ~/Projects/openclaw-development
npm test -- --grep "prompt-defender"
```

---

## Development

### Add New Pattern

1. Edit `service/patterns.py`:
```python
CRITICAL_PATTERNS.append(Pattern(
    pattern=r"your_regex_here",
    severity="critical",
    category="your_category",
    lang="en"
))
```

2. Restart service:
```bash
docker restart prompt-defender
```

3. Test:
```bash
curl -X POST http://127.0.0.1:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"type":"output","tool_name":"test","content":"your test string"}'
```

### Debug Logs

Service logs to stdout (Docker):
```bash
docker logs -f prompt-defender
```

Plugin logs to OpenClaw's logger:
```bash
tail -f ~/.openclaw/logs/*.log
```

---

## Roadmap

### ✅ Phase 1-2: Infrastructure (Complete)
- [x] Plugin skeleton (TypeScript)
- [x] Service skeleton (Python/FastAPI)
- [x] Docker support
- [x] Persistent logging (JSONL)
- [x] `/scan` endpoint
- [x] Basic pattern detection

### 🔄 Phase 3a: prompt-guard (In Progress)
- [ ] Port 500+ YAML patterns to Python
- [ ] Implement tiered scanning engine
- [ ] Add hash cache (deduplication)
- [ ] Add Base64/URL decoding
- [ ] Multi-language support
- [ ] Owner bypass
- [ ] End-to-end testing

### ⏸️ Phase 3b: detect-injection
- [ ] HuggingFace ML model integration
- [ ] OpenAI content moderation
- [ ] Dual-layer scanning (patterns + ML)

### ⏸️ Phase 3c: openclaw-shield
- [ ] Secrets detection (AWS keys, GitHub tokens, etc.)
- [ ] PII detection (SSN, credit cards, emails)
- [ ] Sensitive file patterns

### 📋 Phase 4: Polish
- [ ] Comprehensive test suite
- [ ] Performance benchmarks
- [ ] Admin dashboard
- [ ] Documentation complete

---

## Source Projects

| Project | License | Notes |
|---------|---------|-------|
| [prompt-guard](https://github.com/seojoonkim/prompt-guard) | MIT | 500+ regex patterns, tiered loading |
| [detect-injection](https://github.com/protectai/detect-injection) | Apache 2.0 | ML-based detection, content moderation |
| [openclaw-shield](https://github.com/knostic/openclaw-shield) | Apache 2.0 | Secrets/PII patterns |

---

## Related Projects

| Project | Focus | Complementary? |
|---------|-------|----------------|
| [Knostic Shield](https://github.com/knostic/openclaw-shield) | Secrets, PII, destructive commands | ✅ Yes - different hooks |
| openclaw-prompt-defender | Tool output injection prevention | ✅ Use both for defense-in-depth |

**Recommendation:** Use both plugins together - Shield for input/exec protection, Defender for output validation.

---

## License

MIT License (matching prompt-guard upstream)

---

## Contributing

See [TODO.md](TODO.md) for current task list and implementation priorities.

---

**Repository:** https://github.com/ambushalgorithm/openclaw-prompt-defender  
**Status:** Phase 3a - Implementing prompt-guard patterns  
**OpenClaw Branch:** Custom build with `before_tool_result` hook (`~/Projects/openclaw-development`)
