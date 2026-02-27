# openclaw-air-trust

**The EU AI Act compliance plugin for OpenClaw** — tamper-evident audit trails, consent gating, data tokenization, and prompt injection detection for autonomous AI agents.

[![npm](https://img.shields.io/npm/v/openclaw-air-trust)](https://www.npmjs.com/package/openclaw-air-trust)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Why This Exists

OpenClaw agents can read your email, execute shell commands, send messages, and manage files — autonomously. When something goes wrong, there's no tamper-evident record of what happened, no approval gate for destructive actions, and no protection against prompt injection attacks.

This plugin fixes that. EU AI Act enforcement begins **August 2026**. This is the compliance layer.

## Install

```bash
npm install openclaw-air-trust
```

Then add to your OpenClaw config:

```json
{
  "plugins": ["openclaw-air-trust"]
}
```

## What It Does

| Capability | What It Does | EU AI Act Article |
|---|---|---|
| **Audit Ledger** | HMAC-SHA256 tamper-evident chain of every action | Article 12 (Record-Keeping) |
| **Consent Gate** | Blocks destructive tools until user approves | Article 14 (Human Oversight) |
| **Data Vault** | Tokenizes API keys, PII, credentials before they reach the LLM | Article 10 (Data Governance) |
| **Injection Detector** | Scores inbound messages for 15+ prompt injection patterns | Article 15 (Cybersecurity) |
| **Risk Classifier** | Classifies every tool by risk level (CRITICAL/HIGH/MEDIUM/LOW) | Article 9 (Risk Management) |
| **Compliance Scanner** | Checks agent code against all 6 EU AI Act articles | Articles 9-15 |

## Plugin Tools

Once installed, these tools are available to your OpenClaw agent:

| Tool | Description |
|---|---|
| `air_audit_status` | Get audit chain length, validity, and time range |
| `air_verify_chain` | Verify tamper-evident chain integrity |
| `air_scan_injection` | Scan text for prompt injection patterns |
| `air_classify_risk` | Classify a tool by EU AI Act risk level |
| `air_export_audit` | Export the full audit chain as JSON |
| `air_compliance_check` | Run EU AI Act compliance check on code |

## How It Works

### Audit Ledger (Article 12)

Every tool call, LLM interaction, consent decision, and injection detection gets appended to a tamper-evident chain:

```
Entry 1 → hash₁ ──┐
Entry 2 → hash₂ (prevHash = hash₁) ──┐
Entry 3 → hash₃ (prevHash = hash₂) ──┐
```

Each entry is signed with HMAC-SHA256. Modifying any record breaks the entire chain downstream.

### Consent Gate (Article 14)

When the agent tries to call a destructive tool, the consent gate intercepts and sends an approval request. Risk classification is built-in: critical (code execution), high (file writes, deploys), medium (network/email), low (reads).

### Data Vault (Article 10)

Before tool arguments or context reaches the LLM, the vault scans for sensitive patterns and replaces them with opaque tokens. 14 built-in patterns: OpenAI/Anthropic/AWS/GitHub/Stripe keys, emails, phone numbers, SSNs, credit cards, connection strings, bearer tokens, private keys, and password assignments.

### Injection Detector (Article 15)

Scans inbound messages for 15+ prompt injection patterns: role override, identity hijacking, privilege escalation, safety bypass, jailbreak, data exfiltration, encoding evasion, and more. Three sensitivity levels (low/medium/high) control which patterns are active.

## Configuration

```json
{
  "plugins": {
    "openclaw-air-trust": {
      "enabled": true,
      "gatewayUrl": "https://your-air-gateway.example.com",
      "gatewayKey": "your-api-key",
      "consentGateEnabled": true,
      "consentAlwaysRequire": "exec,spawn,shell,deploy",
      "consentRiskThreshold": "high",
      "consentTimeoutMs": 30000,
      "injectionEnabled": true,
      "injectionSensitivity": "medium",
      "injectionBlockThreshold": 0.8,
      "vaultEnabled": true
    }
  }
}
```

## Standalone Usage

You can also use the components directly without OpenClaw:

```typescript
import { createAirTrustPlugin } from 'openclaw-air-trust/standalone';

const trust = createAirTrustPlugin({
  enabled: true,
  consentGate: { enabled: true, alwaysRequire: ['exec', 'deploy'] },
  injectionDetection: { enabled: true, sensitivity: 'medium', blockThreshold: 0.8 },
});
```

## Part of the AIR Blackbox Ecosystem

| Package | What It Does |
|---|---|
| [air-blackbox-mcp](https://github.com/airblackbox/air-blackbox-mcp) | MCP server for Claude Desktop — 10 compliance tools |
| [air-langchain-trust](https://pypi.org/project/air-langchain-trust/) | Python trust layer for LangChain agents |
| [air-crewai-trust](https://pypi.org/project/air-crewai-trust/) | Python trust layer for CrewAI agents |
| [air-autogen-trust](https://pypi.org/project/air-autogen-trust/) | Python trust layer for AutoGen agents |
| **openclaw-air-trust** | ← You are here |

Learn more at [airblackbox.ai](https://airblackbox.ai)

## Development

```bash
git clone https://github.com/airblackbox/openclaw-air-trust.git
cd openclaw-air-trust
npm install
npm run build
npm test
```

## License

Apache 2.0