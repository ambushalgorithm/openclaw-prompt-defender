# Prompt Defender Test Samples Service

Standalone service for generating dynamic malicious test content to test prompt injection detection.

## Purpose

This service generates realistic tool outputs (HTML, Markdown, JSON, etc.) with embedded malicious content. Used for end-to-end testing of the prompt-defender plugin → scanner → block flow.

## Installation

```bash
cd service-test
pip install -r requirements.txt
```

## Running

```bash
# Development (with auto-reload)
python main.py

# Or using uvicorn directly
uvicorn app:app --host 0.0.0.0 --port 8081 --reload

# Production
uvicorn app:app --host 0.0.0.0 --port 8081
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Index page with links to all samples |
| `/test` | GET | Same as `/` |
| `/test/test` | GET | Dynamic sample (query params control content) |
| `/health` | GET | Health check |

## Query Parameters

| Param | Type | Options | Default | Description |
|-------|------|---------|---------|-------------|
| `filetype` | string | html, md, txt, json, xml | html | Output format |
| `severity` | string | critical, high, medium, low | high | Attack intensity |
| `attack_type` | string | injection, jailbreak, secret, pii, sql, xss, rce | injection | Attack category |
| `obfuscated` | bool | true, false | false | Is attack hidden/encoded? |
| `lang` | string | en, es, fr, de, ru, ko, ja, zh | en | Attack language |
| `clean` | bool | true, false | false | Return clean sample |

**Note:** Use `filetype` (with 'e'), not `filtype`.

## Test Examples

### Prompt Injection (Critical Severity)

```bash
# Critical HTML - bracketed injections like [INST], <<SYS>>
curl "http://localhost:8081/test/test?filetype=html&severity=critical"

# High severity HTML
curl "http://localhost:8081/test/test?filetype=html&severity=high"

# Medium severity HTML
curl "http://localhost:8081/test/test?filetype=html&severity=medium"

# Low severity HTML
curl "http://localhost:8081/test/test?filetype=html&severity=low"
```

### SQL Injection

```bash
# SQL injection in HTML
curl "http://localhost:8081/test/test?filetype=html&attack_type=sql"

# SQL injection in plain text
curl "http://localhost:8081/test/test?filetype=txt&attack_type=sql"

# SQL injection in JSON
curl "http://localhost:8081/test/test?filetype=json&attack_type=sql"
```

### XSS (Cross-Site Scripting)

```bash
# XSS in HTML
curl "http://localhost:8081/test/test?filetype=html&attack_type=xss"

# XSS in plain text
curl "http://localhost:8081/test/test?filetype=txt&attack_type=xss"
```

### RCE (Remote Code Execution)

```bash
# RCE commands in HTML
curl "http://localhost:8081/test/test?filetype=html&attack_type=rce"

# RCE in plain text
curl "http://localhost:8081/test/test?filetype=txt&attack_type=rce"
```

### Jailbreak

```bash
# Jailbreak in plain text
curl "http://localhost:8081/test/test?filetype=txt&attack_type=jailbreak"

# Jailbreak in HTML
curl "http://localhost:8081/test/test?filetype=html&attack_type=jailbreak"
```

### Secret Leaks

```bash
# Secret/API key leak in JSON
curl "http://localhost:8081/test/test?filetype=json&attack_type=secret"

# Secret in plain text
curl "http://localhost:8081/test/test?filetype=txt&attack_type=secret"
```

### PII (Personally Identifiable Information)

```bash
# PII in JSON
curl "http://localhost:8081/test/test?filetype=json&attack_type=pii"

# PII in plain text
curl "http://localhost:8081/test/test?filetype=txt&attack_type=pii"
```

### Obfuscated Attacks

```bash
# Obfuscated (hex-encoded) HTML
curl "http://localhost:8081/test/test?filetype=html&obfuscated=true"

# Obfuscated with critical severity
curl "http://localhost:8081/test/test?filetype=html&severity=critical&obfuscated=true"

# Obfuscated SQL injection
curl "http://localhost:8081/test/test?filetype=html&attack_type=sql&obfuscated=true"
```

### Multi-Language Attacks

```bash
# Spanish
curl "http://localhost:8081/test/test?filetype=txt&lang=es"

# French
curl "http://localhost:8081/test/test?filetype=txt&lang=fr"

# German
curl "http://localhost:8081/test/test?filetype=txt&lang=de"

# Russian
curl "http://localhost:8081/test/test?filetype=txt&lang=ru"

# Korean
curl "http://localhost:8081/test/test?filetype=txt&lang=ko"

# Japanese
curl "http://localhost:8081/test/test?filetype=txt&lang=ja"

# Chinese
curl "http://localhost:8081/test/test?filetype=txt&lang=zh"
```

### Different File Types

```bash
# HTML
curl "http://localhost:8081/test/test?filetype=html&severity=critical"

# Markdown
curl "http://localhost:8081/test/test?filetype=md&severity=critical"

# JSON
curl "http://localhost:8081/test/test?filetype=json&attack_type=secret"

# XML
curl "http://localhost:8081/test/test?filetype=xml&severity=critical"

# Plain text
curl "http://localhost:8081/test/test?filetype=txt&severity=critical"
```

### Clean Samples (Should Pass Scanning)

```bash
# Clean HTML
curl "http://localhost:8081/test/test?clean=true&filetype=html"

# Clean Markdown
curl "http://localhost:8081/test/test?clean=true&filetype=md"

# Clean JSON
curl "http://localhost:8081/test/test?clean=true&filetype=json"
```

## Testing Workflow

1. **Start main scanner service (port 8080):**
   ```bash
   cd ../service && python -m app
   ```

2. **Start test samples service (port 8081):**
   ```bash
   cd service-test && python main.py
   ```

3. **Test scanning directly:**
   ```bash
   # Generate a sample
   SAMPLE=$(curl -s "http://localhost:8081/test/test?filetype=html&severity=critical")
   
   # Send to scanner
   curl -s -X POST "http://localhost:8080/scan" \
     -H "Content-Type: application/json" \
     -d "{\"content\": \"$SAMPLE\"}"
   ```

4. **Test via web_fetch (OpenClaw integration):**
   ```
   web_fetch http://localhost:8081/test/test?filetype=html&severity=critical
   ```

5. **Verify block in scanner logs**

## Running Tests

```bash
# Install test dependencies
pip install -r requirements.txt

# Run all tests
pytest -v

# Run only generator tests
pytest test_generator.py -v

# Run only detection tests
pytest test_detection.py -v

# Run only integration tests
pytest test_detection.py::TestServiceIntegration -v
```

## Port

Default: `8081` (configurable in `main.py`)

## Project Structure

```
service-test/
├── app.py              # FastAPI entry point
├── generator.py        # SampleGenerator class
├── templates.py        # Attack templates
├── main.py             # uvicorn runner
├── test_generator.py   # Unit tests for generator
├── test_detection.py   # Scanner detection + integration tests
├── requirements.txt    # Dependencies
└── README.md          # This file
```
