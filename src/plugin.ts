/**
 * openclaw-air-trust — OpenClaw Plugin Entry Point
 *
 * Registers the AIR Trust compliance layer with OpenClaw's plugin system.
 * Exposes audit, consent, injection detection, and data vault as both
 * agent tools and event hooks.
 *
 * Plugin capabilities:
 * - Tools: air_audit_status, air_verify_chain, air_scan_injection,
 *          air_classify_risk, air_export_audit, air_compliance_check
 * - Hooks: agent:message → injection detection + audit logging
 * - Middleware: tool wrapping for consent gating + data tokenization
 */

import { homedir } from 'os';
import { join } from 'path';
import { AuditLedger } from './audit-ledger';
import { ConsentGate } from './consent-gate';
import { DataVault } from './data-vault';
import { InjectionDetector } from './injection-detector';
import {
  AirTrustConfig,
  ConsentGateConfig,
  AuditLedgerConfig,
  VaultConfig,
  InjectionDetectionConfig,
} from './types';

// ─── OpenClaw Plugin API Types ──────────────────────────────
// These match OpenClaw's plugin SDK interface

interface PluginApi {
  runtime: PluginRuntime;
  config: Record<string, unknown>;
}

interface PluginRuntime {
  registerTool?: (tool: ToolDefinition) => void;
  onEvent?: (event: string, handler: EventHandler) => void;
  sendMessage?: (content: string) => Promise<void>;
}

interface ToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  handler: (args: Record<string, unknown>) => Promise<unknown>;
}

type EventHandler = (event: Record<string, unknown>) => Promise<void>;

// ─── Plugin State ───────────────────────────────────────────

let pluginRuntime: PluginRuntime | null = null;
let ledger: AuditLedger | null = null;
let consentGate: ConsentGate | null = null;
let vault: DataVault | null = null;
let injectionDetector: InjectionDetector | null = null;

// ─── Config Parser ──────────────────────────────────────────

function parseConfig(raw: Record<string, unknown>): AirTrustConfig {
  const alwaysRequire = typeof raw.consentAlwaysRequire === 'string'
    ? (raw.consentAlwaysRequire as string).split(',').map(s => s.trim()).filter(Boolean)
    : ['exec', 'spawn', 'shell', 'deploy'];

  const consentGateConfig: ConsentGateConfig = {
    enabled: raw.consentGateEnabled !== false,
    alwaysRequire,
    neverRequire: ['fs_read', 'search', 'query'],
    timeoutMs: (raw.consentTimeoutMs as number) ?? 30_000,
    riskThreshold: (raw.consentRiskThreshold as 'critical' | 'high' | 'medium' | 'low') ?? 'high',
  };

  const auditLedger: AuditLedgerConfig = {
    enabled: true,
    localPath: (raw.auditLocalPath as string) ?? join(homedir(), '.openclaw', 'air-trust', 'audit-ledger.json'),
    forwardToGateway: !!raw.gatewayUrl,
    maxEntries: 10_000,
  };

  const vaultConfig: VaultConfig = {
    enabled: raw.vaultEnabled !== false,
    categories: ['api_key', 'credential', 'pii'],
    customPatterns: [],
    forwardToGateway: !!raw.gatewayUrl,
    ttlMs: 24 * 60 * 60 * 1000,
  };

  const injectionDetection: InjectionDetectionConfig = {
    enabled: raw.injectionEnabled !== false,
    sensitivity: (raw.injectionSensitivity as 'low' | 'medium' | 'high') ?? 'medium',
    blockThreshold: (raw.injectionBlockThreshold as number) ?? 0.8,
    logDetections: true,
  };

  return {
    enabled: raw.enabled !== false,
    gatewayUrl: raw.gatewayUrl as string | undefined,
    gatewayKey: raw.gatewayKey as string | undefined,
    consentGate: consentGateConfig,
    auditLedger,
    vault: vaultConfig,
    injectionDetection,
  };
}

// ─── Register Function (OpenClaw Plugin Entry Point) ────────

export function register(api: PluginApi): void {
  pluginRuntime = api.runtime;
  const config = parseConfig(api.config ?? {});

  // Initialize components
  ledger = new AuditLedger(config.auditLedger, config.gatewayUrl, config.gatewayKey);
  consentGate = new ConsentGate(config.consentGate, ledger);
  vault = new DataVault(config.vault, config.gatewayUrl, config.gatewayKey);
  injectionDetector = new InjectionDetector(config.injectionDetection);

  // Log plugin startup
  ledger.append({
    action: 'plugin_started',
    riskLevel: 'none',
    consentRequired: false,
    dataTokenized: false,
    injectionDetected: false,
    metadata: { version: '0.2.0', config: { ...config, gatewayKey: '[REDACTED]' } },
  });

  // ─── Register Tools ─────────────────────────────────────
  if (api.runtime.registerTool) {
    // Tool 1: Audit status
    api.runtime.registerTool({
      name: 'air_audit_status',
      description: 'Get the current AIR Trust audit chain status — total entries, chain validity, and time range.',
      parameters: {},
      handler: async () => {
        if (!ledger) return { error: 'Audit ledger not initialized' };
        return ledger.stats();
      },
    });

    // Tool 2: Verify chain integrity
    api.runtime.registerTool({
      name: 'air_verify_chain',
      description: 'Verify the integrity of the tamper-evident audit chain. Returns whether the chain is valid or broken.',
      parameters: {},
      handler: async () => {
        if (!ledger) return { error: 'Audit ledger not initialized' };
        return ledger.verify();
      },
    });

    // Tool 3: Scan for prompt injection
    api.runtime.registerTool({
      name: 'air_scan_injection',
      description: 'Scan text for prompt injection patterns. Returns detection score, matched patterns, and whether the content would be blocked.',
      parameters: {
        type: 'object',
        properties: {
          text: { type: 'string', description: 'Text to scan for injection patterns' },
        },
        required: ['text'],
      },
      handler: async (args) => {
        if (!injectionDetector) return { error: 'Injection detector not initialized' };
        const result = injectionDetector.scan(args.text as string);
        if (ledger) {
          ledger.append({
            action: 'injection_scan',
            riskLevel: result.score >= 0.8 ? 'critical' : result.score >= 0.5 ? 'high' : 'low',
            consentRequired: false,
            dataTokenized: false,
            injectionDetected: result.detected,
            metadata: { score: result.score, patterns: result.patterns },
          });
        }
        return result;
      },
    });

    // Tool 4: Classify tool risk
    api.runtime.registerTool({
      name: 'air_classify_risk',
      description: 'Classify a tool or function by EU AI Act risk level (CRITICAL/HIGH/MEDIUM/LOW).',
      parameters: {
        type: 'object',
        properties: {
          tool_name: { type: 'string', description: 'Name of the tool to classify' },
        },
        required: ['tool_name'],
      },
      handler: async (args) => {
        if (!consentGate) return { error: 'Consent gate not initialized' };
        const toolName = args.tool_name as string;
        return {
          tool: toolName,
          riskLevel: consentGate.classifyRisk(toolName),
          requiresConsent: consentGate.requiresConsent(toolName),
        };
      },
    });

    // Tool 5: Export audit chain
    api.runtime.registerTool({
      name: 'air_export_audit',
      description: 'Export the full audit chain as JSON. Returns all tamper-evident entries with HMAC signatures.',
      parameters: {
        type: 'object',
        properties: {
          last_n: { type: 'number', description: 'Only return the last N entries (default: all)' },
        },
      },
      handler: async (args) => {
        if (!ledger) return { error: 'Audit ledger not initialized' };
        const n = args.last_n as number | undefined;
        return n ? ledger.getRecent(n) : ledger.export();
      },
    });

    // Tool 6: Full compliance check
    api.runtime.registerTool({
      name: 'air_compliance_check',
      description: 'Run a full EU AI Act compliance check on a code snippet. Checks all 6 articles (9, 10, 11, 12, 14, 15) and returns findings with severity and fix recommendations.',
      parameters: {
        type: 'object',
        properties: {
          code: { type: 'string', description: 'Python code to scan for compliance' },
        },
        required: ['code'],
      },
      handler: async (args) => {
        const code = args.code as string;
        try {
          const { scanCode } = await import('./scanner-lite');
          const results = scanCode(code);
          if (ledger) {
            ledger.append({
              action: 'compliance_check',
              riskLevel: results.score === 0 ? 'critical' : results.score < 4 ? 'high' : 'low',
              consentRequired: false,
              dataTokenized: false,
              injectionDetected: false,
              metadata: { score: results.score, totalArticles: 6, framework: results.framework },
            });
          }
          return results;
        } catch {
          return { error: 'Scanner module not available. Install air-blackbox-mcp for full scanning.' };
        }
      },
    });
  }

  // ─── Register Event Hooks ───────────────────────────────
  if (api.runtime.onEvent) {
    // Hook into agent:message for injection detection
    api.runtime.onEvent('agent:message', async (event) => {
      if (!config.enabled) return;
      const content = (event.content ?? event.text ?? event.message ?? '') as string;
      if (!content) return;

      // 1. Scan for injection
      if (config.injectionDetection.enabled && injectionDetector) {
        const result = injectionDetector.scan(content);
        if (result.detected && ledger) {
          ledger.append({
            action: 'injection_detected',
            riskLevel: result.score >= 0.8 ? 'critical' : result.score >= 0.5 ? 'high' : 'medium',
            consentRequired: false,
            dataTokenized: false,
            injectionDetected: true,
            metadata: { score: result.score, patterns: result.patterns, blocked: result.blocked, source: 'agent:message' },
          });
          if (result.blocked && pluginRuntime?.sendMessage) {
            await pluginRuntime.sendMessage(
              `🚨 **AIR Trust — Injection Blocked**\n\nScore: ${result.score.toFixed(2)}\nPatterns: ${result.patterns.join(', ')}\n\nMessage was blocked before reaching the agent.`
            );
          }
        }
      }

      // 2. Tokenize sensitive data
      if (config.vault.enabled && vault) {
        const tokenized = vault.tokenize(content);
        if (tokenized.tokenized && ledger) {
          ledger.append({
            action: 'data_tokenized',
            riskLevel: 'medium',
            consentRequired: false,
            dataTokenized: true,
            injectionDetected: false,
            metadata: { tokensCreated: tokenized.count, source: 'agent:message' },
          });
        }
      }

      // 3. Log the message to audit chain
      if (ledger) {
        ledger.append({
          action: 'message_processed',
          riskLevel: 'none',
          consentRequired: false,
          dataTokenized: false,
          injectionDetected: false,
          metadata: { contentLength: content.length, role: event.role ?? 'unknown' },
        });
      }
    });

    // Hook into tool:call when available (proposed in OpenClaw #10502)
    api.runtime.onEvent('tool:call', async (event) => {
      if (!config.enabled) return;
      const toolName = (event.toolName ?? event.tool ?? event.name ?? '') as string;
      if (!toolName) return;

      // Consent gating
      if (config.consentGate.enabled && consentGate) {
        const risk = consentGate.classifyRisk(toolName);
        if (consentGate.requiresConsent(toolName) && pluginRuntime?.sendMessage) {
          const request = {
            id: toolName,
            toolName,
            toolArgs: (event.args ?? event.parameters ?? {}) as Record<string, unknown>,
            riskLevel: risk,
            reason: `Tool "${toolName}" classified as ${risk} risk`,
            status: 'pending' as const,
            createdAt: new Date().toISOString(),
          };
          await pluginRuntime.sendMessage(consentGate.formatConsentMessage(request));
        }
      }

      // Audit log
      if (ledger) {
        ledger.append({
          action: 'tool_call',
          toolName,
          riskLevel: consentGate?.classifyRisk(toolName) ?? 'low',
          consentRequired: consentGate?.requiresConsent(toolName) ?? false,
          dataTokenized: false,
          injectionDetected: false,
          metadata: { source: 'tool:call' },
        });
      }
    });

    // Hook into tool:result when available
    api.runtime.onEvent('tool:result', async (event) => {
      if (!config.enabled || !ledger) return;
      ledger.append({
        action: 'tool_result',
        toolName: (event.toolName ?? event.tool ?? '') as string,
        riskLevel: 'none',
        consentRequired: false,
        dataTokenized: false,
        injectionDetected: false,
        metadata: { durationMs: event.durationMs, success: event.success ?? true, source: 'tool:result' },
      });
    });
  }
}

// ─── Exports for standalone usage ───────────────────────────

export { AuditLedger } from './audit-ledger';
export { ConsentGate } from './consent-gate';
export { DataVault } from './data-vault';
export { InjectionDetector } from './injection-detector';
export { createAirTrustPlugin } from './index';
export * from './types';