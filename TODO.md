# openclaw-prompt-defender TODO

**Current Phase:** 3a - prompt-guard Implementation  
**Last Updated:** 2026-02-14

---

## ✅ Phase 1: Skeleton (COMPLETE)

- [x] Create plugin/ directory (TypeScript)
- [x] Create service/ directory (Python/FastAPI)
- [x] Test service locally (works)

---

## ✅ Phase 2: Docker Setup & Testing (COMPLETE)

- [x] Create Dockerfile for service
- [x] Build plugin ✅
- [x] Load plugin in OpenClaw Docker ✅
- [x] Service accessible from plugin ✅
- [x] Test blocking behavior ✅
- [x] Persistent logging to ~/.openclaw/logs/ ✅

---

## 🔄 Phase 3a: prompt-guard Implementation (IN PROGRESS)

### Week 1: Pattern Conversion (Starting Now)

- [ ] Create `service/patterns.py` module
  - [ ] Define `Pattern` NamedTuple (pattern, severity, category, lang)
  - [ ] Port `critical.yaml` → `CRITICAL_PATTERNS` list (~30 patterns)
  - [ ] Port `high.yaml` → `HIGH_PATTERNS` list (~70 patterns)
  - [ ] Port `medium.yaml` → `MEDIUM_PATTERNS` list (~200+ patterns)
  - [ ] Add pattern validation (test all regex patterns compile)
  - [ ] Add pattern count assertions (verify all patterns ported)

**Acceptance Criteria:**
- ✅ All 500+ patterns converted from YAML to Python
- ✅ Each pattern has: pattern (str), severity (str), category (str), lang (str)
- ✅ No regex compilation errors
- ✅ Unit test: pattern count matches YAML source

---

### Week 2: Scanning Engine

- [ ] Create `service/scanner.py` module
  - [ ] Implement `TieredScanner` class
  - [ ] Add `scan(content, tier)` method
    - [ ] Tier 0: Critical only (~30 patterns)
    - [ ] Tier 1: Critical + High (~100 patterns)
    - [ ] Tier 2: All patterns (~300+ patterns)
  - [ ] Implement hash cache (SHA-256, 16 chars)
    - [ ] Cache structure: `{content_hash: (is_dangerous, matches)}`
    - [ ] Add cache hit/miss tracking
  - [ ] Add `_scan_tier(content, patterns)` helper
  - [ ] Add progressive loading logic
  - [ ] Add performance tracking (scan duration per tier)

**Acceptance Criteria:**
- ✅ Tier 0 scan: <5ms average
- ✅ Tier 1 scan: <15ms average
- ✅ Tier 2 scan: <50ms average
- ✅ Hash cache reduces duplicate scans by ~70%
- ✅ Unit test: verify tier progression logic
- ✅ Integration test: scan real injection examples

---

### Week 3: Advanced Features

- [ ] Create `service/decoder.py` module
  - [ ] Implement Base64 detection and decoding
  - [ ] Implement URL encoding detection
  - [ ] Implement Unicode escape detection
  - [ ] Add `decode_and_scan(content)` function
  - [ ] Return `List[Dict]` with encoding type + decoded content

- [ ] Create `service/config.py` module
  - [ ] Define `Config` class
  - [ ] Add feature flags structure
  - [ ] Add `load_from_headers()` method (plugin passes config)
  - [ ] Add validation (check required fields)

- [ ] Update `service/app.py`
  - [ ] Add owner bypass check (before scanning)
  - [ ] Integrate `TieredScanner`
  - [ ] Add feature flag checking
  - [ ] Update `/scan` endpoint to use new scanner
  - [ ] Add tier selection based on config
  - [ ] Add decoded content scanning

- [ ] Update `plugin/src/index.ts`
  - [ ] Pass user ID in request headers (`X-User-ID`)
  - [ ] Pass feature config in headers (`X-Config`)
  - [ ] Add feature flag checking before calling service
  - [ ] Handle sanitized content (future: Phase 3b)

**Acceptance Criteria:**
- ✅ Owner bypass: trusted users skip scanning (0ms overhead)
- ✅ Base64 encoded attacks are detected and decoded
- ✅ URL encoded attacks are detected and decoded
- ✅ Feature flags toggle scanning on/off
- ✅ Plugin passes user ID and config to service
- ✅ Unit test: owner bypass logic
- ✅ Unit test: Base64/URL decoding

---

### Week 4: Testing & Documentation

- [ ] **End-to-End Testing (Docker)**
  - [ ] Write Docker Compose setup (service + OpenClaw)
  - [ ] Test Tier 0 detection (critical patterns)
  - [ ] Test Tier 1 detection (high patterns)
  - [ ] Test Tier 2 detection (medium patterns)
  - [ ] Test owner bypass (trusted user skips scanning)
  - [ ] Test hash cache (repeated content skipped)
  - [ ] Test Base64 encoded attacks
  - [ ] Test URL encoded attacks
  - [ ] Test multi-language patterns (en, ko, ja, zh)
  - [ ] Test fail-open behavior (service down)
  - [ ] Validate logging (threats.jsonl + scans.jsonl)

- [ ] **Performance Benchmarks**
  - [ ] Measure Tier 0 scan time (target: <5ms)
  - [ ] Measure Tier 1 scan time (target: <15ms)
  - [ ] Measure Tier 2 scan time (target: <50ms)
  - [ ] Measure cache hit rate (target: >70% reduction)
  - [ ] Measure end-to-end latency (plugin → service → response)

- [ ] **Documentation**
  - [ ] Update README with prompt-guard features
  - [ ] Document all pattern categories (critical/high/medium)
  - [ ] Add usage examples for each tier
  - [ ] Document configuration options
  - [ ] Add troubleshooting section
  - [ ] Update API reference with new fields

- [ ] **Code Quality**
  - [ ] Add type hints to all Python functions
  - [ ] Add docstrings to all public methods
  - [ ] Run linter (flake8 or ruff)
  - [ ] Format code (black)
  - [ ] Add unit tests (target: >80% coverage)

**Acceptance Criteria:**
- ✅ All 500+ patterns tested against real injection examples
- ✅ Performance targets met (tier scan times)
- ✅ Docker end-to-end tests passing
- ✅ Documentation complete and accurate
- ✅ Code formatted and linted
- ✅ Unit test coverage >80%

---

## ⏸️ Phase 3b: detect-injection Integration (NEXT)

**Prerequisites:** Phase 3a complete

- [ ] Add HuggingFace API integration
  - [ ] Add `HF_TOKEN` environment variable
  - [ ] Implement ProtectAI DeBERTa classifier call
  - [ ] Parse ML model response (SAFE vs INJECTION score)
  - [ ] Add confidence threshold (default: 0.85)

- [ ] Add OpenAI content moderation
  - [ ] Add `OPENAI_API_KEY` environment variable
  - [ ] Implement omni-moderation endpoint call
  - [ ] Parse 13 content categories
  - [ ] Add severity mapping

- [ ] Dual-layer scanning
  - [ ] Run pattern matching first (fast)
  - [ ] Run ML detection if patterns unclear
  - [ ] Combine results (patterns + ML score)
  - [ ] Add weighted decision logic

- [ ] Feature flag: `ml_detection`
  - [ ] Enable/disable ML scanning
  - [ ] Graceful fallback if HF_TOKEN missing

- [ ] Feature flag: `content_moderation`
  - [ ] Enable/disable OpenAI moderation
  - [ ] Graceful fallback if OPENAI_API_KEY missing

**Acceptance Criteria:**
- ✅ ML detection accuracy >99% on test set
- ✅ OpenAI moderation detects all 13 categories
- ✅ Feature flags work independently
- ✅ Graceful degradation when API keys missing

---

## ⏸️ Phase 3c: openclaw-shield Integration (LATER)

**Prerequisites:** Phase 3b complete

- [ ] Add secrets detection
  - [ ] Port SECRET_PATTERNS from openclaw-shield
  - [ ] Add AWS keys, GitHub tokens, OpenAI keys, etc.
  - [ ] Add JWT, bearer token detection

- [ ] Add PII detection
  - [ ] Port PII_PATTERNS from openclaw-shield
  - [ ] Add email, SSN, credit card detection
  - [ ] Add phone number detection (US + international)

- [ ] Add destructive command detection
  - [ ] Port destructive command patterns
  - [ ] Add `rm -rf`, `DROP TABLE`, etc.

- [ ] Add sensitive file patterns
  - [ ] Port sensitive file patterns
  - [ ] Add `.env`, `.pem`, `.key`, etc.

- [ ] Feature flag: `secret_scanner`
  - [ ] Enable/disable secrets detection
  - [ ] Add redaction support (sanitize action)

**Acceptance Criteria:**
- ✅ All openclaw-shield patterns ported
- ✅ Secrets detected and logged
- ✅ PII detected and logged
- ✅ Feature flag works independently

---

## 📋 Phase 4: Polish & Production (FINAL)

**Prerequisites:** All Phase 3 features complete

- [ ] Admin dashboard
  - [ ] Web UI for viewing logs
  - [ ] Real-time threat feed
  - [ ] Statistics visualization

- [ ] Performance optimization
  - [ ] Profile slow patterns
  - [ ] Optimize regex compilation
  - [ ] Add pattern caching

- [ ] Multi-language expansion
  - [ ] Add more languages (es, fr, de, etc.)
  - [ ] Test non-Latin scripts

- [ ] Comprehensive test suite
  - [ ] Unit tests for all modules
  - [ ] Integration tests for all features
  - [ ] E2E tests for all scenarios
  - [ ] Performance regression tests

- [ ] Production deployment
  - [ ] Kubernetes manifests
  - [ ] Helm chart
  - [ ] Monitoring/alerting setup
  - [ ] Log aggregation

**Acceptance Criteria:**
- ✅ Full test coverage (>90%)
- ✅ Production-ready deployment
- ✅ Admin dashboard functional
- ✅ Documentation complete

---

## Notes

### Testing Strategy
- **Unit tests**: Individual functions and classes
- **Integration tests**: Service endpoints with mocked dependencies
- **E2E tests**: Full Docker stack (plugin + service + OpenClaw)
- **All E2E testing done in Docker containers**

### Development Workflow
1. Update TODO.md before starting work
2. Implement feature
3. Write tests
4. Update documentation
5. Mark task complete in TODO.md
6. Commit and push

### Branch Strategy
- Development happens on `master`
- Testing uses `~/Projects/openclaw-development` (custom OpenClaw with `before_tool_result` hook)
- Production ready when Phase 4 complete

---

**Next Task:** Week 1: Pattern Conversion - Create `service/patterns.py`
