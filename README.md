# 🛡️ OpenClaw Prompt Defender

⚠️🚧 **UNDER CONSTRUCTION** 🚧⚠️

This repository is actively being worked on and is not meant for use until features are completed. Use at your own risk!

---

<p align="center">
  <img src="https://img.shields.io/badge/Plugin-TypeScript-blue?style=for-the-badge&logo=typescript" alt="TypeScript">
  <img src="https://img.shields.io/badge/Scanner-Python-cyan?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/OpenClaw-v2026.2.4-green?style=for-the-badge" alt="OpenClaw">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

> Prompt injection detection and jailbreak prevention for OpenClaw — scans tool outputs before they reach the LLM.

## ✨ What is this?

**OpenClaw Prompt Defender** is a security plugin that protects your AI assistant from malicious inputs hidden in tool outputs. It intercepts results from tools like `web_fetch`, `exec`, and `read` before they reach the LLM, scanning for:

- 🎯 **Prompt injection attacks** — Attempts to override your AI's instructions
- 🔓 **Jailbreak attempts** — Tricks to bypass safety guidelines  
- 🔑 **Secret leaks** — Accidental exposure of API keys, tokens, passwords
- 👤 **PII exposure** — Personal information that shouldn't be shared
- 💉 **Malicious content** — XSS, SQL injection, RCE attempts

## ⚠️ Requirements

This plugin works with any scanner service that implements the required API.

| Component | Status | Description |
|-----------|--------|-------------|
| **openclaw-prompt-defender-plugin** | **Required** | This plugin — drops into OpenClaw |
| **Scanner service** | **Recommended** | Any service that implements `/scan` endpoint (default: prompt-defender-scanner) |

### Recommended Scanner

The [prompt-defender-scanner](https://github.com/ambushalgorithm/prompt-defender-scanner) is the recommended scanner:

```bash
# Clone
git clone https://github.com/ambushalgorithm/prompt-defender-scanner.git
cd prompt-defender-scanner

# Option A: Run directly
pip install -r requirements.txt
python -m app
# Scanner runs on http://localhost:8080

# Option B: Docker
docker build -t prompt-defender-scanner .
docker run -d --name prompt-defender-scanner -p 8080:8080 prompt-defender-scanner
```

### Using a Custom Scanner

The plugin calls `POST /scan` with:
```json
{"type": "output", "content": "...", "tool_name": "..."}
```

Expected response:
```json
{"action": "allow"}  // or "block" with reason
```

Configure your custom scanner:
```json
{
  "plugins": {
    "prompt-defender": {
      "service_url": "http://your-scanner:8080"
    }
  }
}
```

### Step 1: Install the Plugin

```bash
# Clone this repo
git clone https://github.com/ambushalgorithm/openclaw-prompt-defender-plugin.git
cd openclaw-prompt-defender-plugin

# Copy the plugin into your OpenClaw plugins directory
cp -r plugin ~/.openclaw/plugins/prompt-defender
```

### Step 2: Configure OpenClaw

Add to your OpenClaw config:

```json
{
  "plugins": {
    "enabled": ["prompt-defender"],
    "prompt-defender": {
      "service_url": "http://localhost:8080"
    }
  }
}
```

The plugin defaults to `http://localhost:8080` — if you run the scanner there, no config needed!

## 🏗️ Architecture

```
User Input → OpenClaw → Tool Execution → [Plugin] → [Scanner Service] → LLM
                                              ↓
                                      Block if malicious
```

- **Plugin** (TypeScript) — Runs in OpenClaw, intercepts tool results, calls scanner API
- **Scanner** (Python) — Standalone service that performs pattern matching & detection

## 🔍 Detection Methods

| Method | Patterns | Use Case |
|--------|----------|----------|
| **prompt_guard** | 500+ regex | Core injection detection |
| **ml_detection** | HuggingFace DeBERTa | Advanced ML-based detection |
| **secret_scanner** | 50+ patterns | API keys, tokens, passwords |
| **content_moderation** | OpenAI API | Policy violations |

Each is independently toggleable via feature flags.

## 🧪 Testing the Scanner Directly

```bash
# Scan text for threats
curl -X POST "http://localhost:8080/scan" \
  -H "Content-Type: application/json" \
  -d '{"type": "output", "content": "Hello world", "tool_name": "read"}'
```

### Response

```json
{
  "action": "allow",
  "matches": []
}
```

### Blocked Content

```json
{
  "action": "block",
  "reason": "Potential prompt injection detected",
  "matches": [
    {
      "pattern": "[INST]",
      "type": "prompt_injection",
      "severity": "critical"
    }
  ]
}
```

## 📁 Project Structure

```
openclaw-prompt-defender-plugin/
├── plugin/                 # TypeScript plugin
│   ├── src/
│   │   └── index.ts       # before_tool_result hook
│   └── openclaw.plugin.json
│
├── docs/
│   └── DESIGN.md          # Architecture details
│
├── docker-compose.yml      # For running both together (optional)
│
└── README.md
```

**Scanner lives in:** [prompt-defender-scanner](https://github.com/ambushalgorithm/prompt-defender-scanner)

## 🔧 Configuration

```json
{
  "service_url": "http://localhost:8080",
  "timeout_ms": 5000,
  "fail_open": true,
  "scan_enabled": true,
  "features": {
    "prompt_guard": true
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `service_url` | `http://localhost:8080` | Scanner API endpoint |
| `timeout_ms` | `5000` | Request timeout |
| `fail_open` | `true` | Allow if scanner unavailable |
| `scan_enabled` | `true` | Enable/disable scanning |
| `features.prompt_guard` | `true` | Toggle detection methods |

## 🐳 Docker Compose (Optional)

To run both OpenClaw and the scanner together:

```yaml
# docker-compose.yml
version: "3.8"

services:
  openclaw:
    image: openclaw/openclaw:latest
    ports:
      - "3000:3000"
    volumes:
      - ~/.openclaw:/home/clawdbot/.openclaw

  scanner:
    image: ghcr.io/ambushalgorithm/prompt-defender-scanner
    ports:
      - "8080:8080"
```

```bash
docker-compose up -d
```

## 🤝 Contributing

Contributions welcome! The scanner logic lives in [prompt-defender-scanner](https://github.com/ambushalgorithm/prompt-defender-scanner).

## 📜 License

MIT License

## 🔗 Related Projects

- [prompt-defender-scanner](https://github.com/ambushalgorithm/prompt-defender-scanner) — Standalone scanner service
- [prompt-injection-testing](https://github.com/ambushalgorithm/prompt-injection-testing) — Test sample generation
- [prompt-guard](https://github.com/seojoonkim/prompt-guard) — Regex patterns
- [detect-injection](https://github.com/protectai/detect-injection) — ML detection

---

<p align="center">
  <sub>Built with 🔒 for secure AI assistants</sub>
</p>
