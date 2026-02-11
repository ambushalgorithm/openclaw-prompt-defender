# openclaw-prompt-defender

Built with: Kimi K2.5 (via Ollama Cloud) • OpenClaw v2026.2.4

Unified prompt injection detection plugin for OpenClaw — combining the best of `prompt-guard` and `detect-injection` into a single, cohesive security layer.

## Overview

This plugin integrates directly with OpenClaw to provide comprehensive content safety scanning across both input (user messages) and output (agent responses). It consolidates two proven approaches:

| Source | Strength | Ported |
|--------|----------|--------|
| **prompt-guard** | Fast pattern matching, 70% token reduction, SHIELD categories, owner bypass | ✅ |
| **detect-injection** | Dual-layer scanning, HF-based vector detection, safety categories | ✅ |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    OpenClaw Gateway                      │
│                     (your instance)                      │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│              openclaw-prompt-defender                    │
│  ┌─────────────────┐    ┌─────────────────────────────┐ │
│  │  Input Scanner  │───▶│  Pattern Engine (fast)      │ │
│  │  (user msgs)    │    │  • SHIELD categories        │ │
│  └─────────────────┘    │  • 500+ patterns            │ │
│                         │  • Owner bypass             │ │
│  ┌─────────────────┐    ├─────────────────────────────┤ │
│  │  Output Scanner │───▶│  Vector Engine (HF-based)   │ │
│  │  (agent replies)│    │  • Semantic detection       │ │
│                         │  • Safety classification      │ │
│                         └─────────────────────────────┘ │
│                          ↓ Unified Response             │
│  ┌────────────────────────────────────────────────────┐ │
│  │           Decision: ALLOW / BLOCK / REVIEW          │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## Project Plan

### Phase 1: Foundation (Week 1)
- [ ] Set up project structure and packaging
- [ ] Create OpenClaw plugin manifest
- [ ] Port `prompt-guard` pattern matcher and SHIELD categories
- [ ] Port `detect-injection` HF vector loader and safety classifiers
- [ ] Implement unified configuration system

### Phase 2: Integration (Week 2)
- [ ] Implement dual-layer scanning pipeline
- [ ] Port owner bypass system (by user ID)
- [ ] Add OpenClaw hook integration (`message:received`, `message:sending`)
- [ ] Create unified severity scoring
- [ ] Build async batch processing for vector checks

### Phase 3: Features (Week 3)
- [ ] Port hash cache for 90% token reduction on repeated requests
- [ ] Implement 10-language support from prompt-guard
- [ ] Add audit logging integration with openclaw-cmdlog
- [ ] Create admin dashboard/status endpoint
- [ ] Port tiered pattern loading (70% token reduction)

### Phase 4: Polish (Week 4)
- [ ] Comprehensive test suite
- [ ] Documentation and examples
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

## Configuration

```json
{
  "plugins": {
    "prompt-defender": {
      "enabled": true,
      "mode": "dual", // "pattern", "vector", or "dual"
      "owner_ids": ["1461460866850357345"],
      "input_scanning": true,
      "output_scanning": true,
      "shield_categories": ["INJECTION", "JAILBREAK", "OBFUSCATION"],
      "cache_enabled": true,
      "languages": ["en", "es", "fr", "de", "zh", "ja", "ko", "ru", "ar", "pt"]
    }
  }
}
```

## Quick Start

```bash
# 1. Clone and install
cd ~/Projects/openclaw-prompt-defender
pip install -e .

# 2. Configure OpenClaw
# Add to ~/.openclaw/openclaw.json (see Configuration above)

# 3. Restart OpenClaw
openclaw gateway restart
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .
black --check .
```

## Roadmap

- **v0.1.0** — Core dual-layer scanning, owner bypass, OpenClaw integration
- **v0.2.0** — Hash cache, multi-language support, audit logging
- **v0.3.0** — Admin dashboard, metrics, performance optimizations
- **v1.0.0** — Stable release, full test coverage, documentation

## License

Dual-licensed under MIT and Apache 2.0 (to match source projects).

---

*Project created: 2026-02-11*
*Status: Phase 1 - Foundation*
