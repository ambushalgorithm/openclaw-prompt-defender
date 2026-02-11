# Design Document — openclaw-prompt-defender

**Project:** openclaw-prompt-defender  
**Date:** 2026-02-11  
**Status:** Architecture defined, ready for Phase 1 implementation  
**Repository:** https://github.com/crayon-doing-petri/openclaw-prompt-defender (private)

---

## Executive Summary

A unified security plugin for OpenClaw that provides **bidirectional content filtering** — scanning both user input and tool output before they reach the LLM model.

**Core innovation:** Two-layer architecture where a thin TypeScript plugin (in OpenClaw sandbox) delegates all security work to a Python/FastAPI service (with full host access) via HTTP.

---

## Key Design Decisions

### 1. Plugin Gateway Pattern (Selected)

| Aspect | Rationale |
|--------|-----------|
| **Thin plugin + HTTP service** | Plugin stays in sandbox; service does heavy lifting |
| **Language freedom** | Can leverage existing Python tools (prompt-guard, detect-injection) |
| **1Password access** | Service layer can spawn `op` CLI; plugin cannot |
| **Future extensibility** | Add new endpoints without plugin redeploy |

**Alternatives considered:**
- Pure TypeScript in plugin: Limited by sandbox, can't use 1Password CLI
- Separate plugin per tool: Too many moving pieces
- Generic mega-plugin: Becomes kitchen sink, hard to debug

### 2. Bidirectional Filtering

**Two hooks, shared scan engine:**

```
User Input  ──▶  message:received  ──▶  /scan (profile=input/strict)
                                                     │
                                                     ▼
                                             ┌───────────────┐
                                             │ Unified Scan  │
                                             │ Engine        │
                                             └───────┬───────┘
                                                     │
                                                     ▼
Tool Output ──▶  tool_result:persist ──▶  /scan (profile=output/moderate)
```

**Input profile (strict):**
- Prompt injection detection
- Jailbreak prevention
- SHIELD categories
- Owner bypass

**Output profile (moderate):**
- PII scrubbing
- Content safety
- Size limiting
- Malicious URL detection

### 3. Unified Service Endpoint

Single `/scan` endpoint with `type` parameter:

```bash
POST /scan
{
  "type": "input" | "output",
  "content": "...",
  "user_id": "...",
  "tool_name": "..."  # for output type
}
```

Response:
```json
{
  "action": "allow" | "block" | "sanitize",
  "sanitized": "modified content",
  "severity": "none" | "low" | "medium" | "high" | "critical",
  "reasons": ["..."]
}
```

### 4. Fail-Open Strategy

| Scenario | Behavior |
|----------|----------|
| Service unreachable | Allow/sanitize minimally, log warning |
| Timeout exceeded | Allow/sanitize minimally, log warning |
| Service error | Allow/sanitize minimally, log error |
| Scan success | Follow scan decision (block/sanitize/allow) |

**Rationale:** Prevent security filter outage from blocking all agent functionality.

---

## Hook Verification Results

✅ **All required hooks verified in current fork**

| Hook | Available In | Can Modify? | Can Cancel? |
|------|--------------|-------------|-------------|
| `message:received` | PR #12637 (merged) | ✅ Yes | ✅ Yes |
| `tool_result:persist` | Core OpenClaw | ✅ Yes | ❌ No* |

*Note: `tool_result_persist` can return empty/sanitized but can't fully cancel. Model will see empty content rather than nothing.

**Important:** No additional fork changes needed. PR #12637 already merged into `feat/message-received`. Tool output filtering works via `tool_result:persist` (fires when tool results persisted to session transcript — model reads from transcript).

---

## Implementation Phases

### Phase 1: Foundation (Week 1)
- [ ] Set up `plugin/` and `service/` directories
- [ ] Initialize npm/pip projects with configs
- [ ] Create OpenClaw plugin manifest (`openclaw.plugin.json`)
- [ ] Implement `/scan` endpoint with type switching
- [ ] Port `prompt-guard` pattern matcher to Python
- [ ] Port `detect-injection` vector scanner to Python
- [ ] Owner bypass system

### Phase 2: Integration (Week 2)
- [ ] TypeScript HTTP client for service
- [ ] `message:received` handler implementation
- [ ] `tool_result:persist` handler implementation
- [ ] Input profile (strict) — injection, jailbreak
- [ ] Output profile (moderate) — PII, content safety
- [ ] End-to-end test with OpenClaw

### Phase 3: Features (Week 3)
- [ ] Hash cache for 90% token reduction
- [ ] 1Password CLI integration in service
- [ ] Service health check endpoint
- [ ] Audit logging (openclaw-cmdlog)
- [ ] Multi-language support (10 languages)
- [ ] Load/performance testing

### Phase 4: Polish (Week 4)
- [ ] Comprehensive test suite
- [ ] Documentation: setup guide, API docs
- [ ] Deployment scripts
- [ ] GitHub Actions CI/CD
- [ ] v0.1.0 release

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Plugin** | TypeScript / Node.js | OpenClaw integration, hooks |
| **Service** | Python / FastAPI | Security scanning, host access |
| **Pattern Engine** | Ported from prompt-guard | Fast regex matching |
| **Vector Engine** | Ported from detect-injection | HF-based semantic detection |
| **Secrets** | 1Password CLI | API keys, tokens |
| **Config** | JSON Schema | Plugin configuration |

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Service latency | Slow agent responses | Async scanning, timeout handling, caching |
| Service downtime | No security filtering | Fail-open strategy, no blocking of messages |
| Pattern updates | Missed attacks | Separate pattern update mechanism |
| False positives | User frustration | Owner bypass, adjustable thresholds |

---

## Success Criteria

- [ ] User input filtering works (injection detection)
- [ ] Tool output filtering works (PII scrubbing)
- [ ] Owner bypass functional (trusted users exempt)
- [ ] Service fails gracefully (fail-open)
- [ ] Sub-100ms scan latency
- [ ] 90% token reduction via hash cache

---

## Current Status

| Milestone | Status |
|-----------|--------|
| Architecture defined | ✅ Complete |
| Hook verification | ✅ Complete |
| Project structure | ✅ Ready |
| Phase 1 implementation | 🔄 Ready to start |
| GitHub repo | ✅ Private, URL documented |

---

*Document generated: 2026-02-11*  
*OpenClaw Version: 2026.2.9*  
*OpenClaw Branch: feat/message-received (PR #12637 merged)*
