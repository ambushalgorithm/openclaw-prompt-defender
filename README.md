# openclaw-prompt-defender

Built with: Claude Sonnet 4.5 • OpenClaw v2026.2.4 (custom branch with `before_tool_result` hook)

**Prompt injection detection and jailbreak prevention** for OpenClaw — combining the best detection methods from `prompt-guard`, `detect-injection`, and `openclaw-shield` using the **Plugin Gateway Pattern**.

**Current Status:** 🔄 **Phase 3a** - Implementing prompt-guard patterns (500+ regex patterns across 3 tiers)

**Testing:** All end-to-end tests run in Docker containers for reproducibility.

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

## How It Works

**High-Level Flow:**

1. Tool executes (e.g., `web_fetch`, `exec`, `read`)
2. `before_tool_result` hook intercepts the output
3. Plugin sends output to security service for scanning
4. Service checks patterns (and optionally ML models)
5. Returns verdict: ALLOW, BLOCK, or SANITIZE
6. Plugin enforces verdict before LLM sees the content

**Why separate plugin and service?**
- Plugin (TypeScript) → Runs in OpenClaw's sandbox, handles hooks
- Service (Python) → Runs on host, has access to ML libraries and pattern matching

See [docs/DESIGN.md](docs/DESIGN.md) for detailed architecture and algorithms.

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

## Quick Start

### Development Setup (Local)

```bash
# 1. Install service dependencies
cd ~/Projects/openclaw-plugins/openclaw-prompt-defender/service
pip install -r requirements.txt

# 2. Start the service
python app.py
# → Service running on http://127.0.0.1:8080

# 3. Build plugin (separate terminal)
cd ~/Projects/openclaw-plugins/openclaw-prompt-defender/plugin
npm install && npm run build

# 4. Configure OpenClaw (~/.openclaw/openclaw.json)
# See Configuration section below

# 5. Restart OpenClaw
openclaw gateway restart
```

### Docker Testing (End-to-End)

**All testing is done in Docker containers** to ensure reproducibility:

```bash
# Start service container
cd ~/Projects/openclaw-plugins/openclaw-prompt-defender/service
docker build -t prompt-defender:latest .
docker run -d \
  -p 8080:8080 \
  -v ~/.openclaw/logs:/root/.openclaw/logs \
  --name prompt-defender \
  prompt-defender:latest

# Test the service
curl http://localhost:8080/health

# Run end-to-end tests
docker exec -it prompt-defender pytest tests/
```

**Note:** Plugin integration testing requires OpenClaw running with the `before_tool_result` hook. See [Testing](#testing) section.

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

Patterns are loaded progressively for performance:

- **Tier 0** (Critical): ~30 patterns, always loaded, <5ms
- **Tier 1** (High): +70 patterns, loaded after critical match, <15ms
- **Tier 2** (Medium): +200 patterns, deep scan mode, <50ms

Result: ~70% faster scanning while maintaining accuracy. See [DESIGN.md](docs/DESIGN.md) for algorithm details.

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

## Detection Categories

**Tier 0 (Critical):** Secret exfiltration, SQL injection, XSS, system destruction  
**Tier 1 (High):** Instruction override, jailbreak, system impersonation  
**Tier 2 (Medium):** Role manipulation, authority impersonation, context hijacking

See [DESIGN.md](docs/DESIGN.md) for complete pattern category breakdown.

---

## API Endpoints

- `POST /scan` - Scan content for threats (returns action: allow/block/sanitize)
- `GET /health` - Health check
- `GET /stats?hours=24` - Threat statistics
- `GET /patterns` - List active patterns

See [DESIGN.md](docs/DESIGN.md) for detailed API documentation.

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

All end-to-end testing is done in Docker containers:

```bash
# Build and start service
cd service
docker build -t prompt-defender:latest .
docker run -d -p 8080:8080 --name prompt-defender prompt-defender:latest

# Run tests inside container
docker exec -it prompt-defender pytest tests/

# Check logs
docker logs -f prompt-defender
```

See [TODO.md](TODO.md) for detailed testing checklist.

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
