/**
 * openclaw-air-trust — Lightweight Compliance Scanner
 *
 * Checks Python AI agent code for EU AI Act compliance across
 * Articles 9, 10, 11, 12, 14, and 15. Detects frameworks and
 * trust layer presence.
 */

interface ScanResult {
  score: number;
  totalArticles: number;
  framework: string;
  hasTrustLayer: boolean;
  findings: Finding[];
}

interface Finding {
  article: number;
  title: string;
  status: 'pass' | 'fail';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  fix: string;
}

function detectFramework(code: string): string {
  if (/from\s+langchain|import\s+langchain/i.test(code)) return 'langchain';
  if (/from\s+crewai|import\s+crewai/i.test(code)) return 'crewai';
  if (/from\s+autogen|import\s+autogen/i.test(code)) return 'autogen';
  if (/from\s+openai|import\s+openai|OpenAI\(/i.test(code)) return 'openai';
  if (/RAGPipeline|VectorStore|Retriever|from\s+llama_index/i.test(code)) return 'rag';
  return 'unknown';
}

function detectTrustLayer(code: string): boolean {
  return /air[-_]?(?:trust|blackbox|compliance|langchain|crewai|autogen)/i.test(code)
    || /AirTrust|AuditLedger|ConsentGate|DataVault|InjectionDetector/i.test(code);
}

function checkArticle9(code: string): Finding {
  const has = /risk[-_]?(?:assess|classif|level|score|evaluat)/i.test(code) || /ConsentGate|classify[-_]?risk/i.test(code);
  return { article: 9, title: 'Risk Management System', status: has ? 'pass' : 'fail', severity: 'critical',
    description: has ? 'Risk classification detected' : 'No risk management system found. EU AI Act requires continuous risk assessment.',
    fix: 'Add AIR ConsentGate for automatic risk classification of all tool calls.' };
}

function checkArticle10(code: string): Finding {
  const has = /data[-_]?(?:valid|clean|govern|quality|pipeline)/i.test(code) || /DataVault|tokenize|detokenize/i.test(code);
  return { article: 10, title: 'Data Governance', status: has ? 'pass' : 'fail', severity: 'high',
    description: has ? 'Data governance measures detected' : 'No data governance found. EU AI Act requires data quality and privacy controls.',
    fix: 'Add AIR DataVault to tokenize PII and credentials before they reach the LLM.' };
}

function checkArticle11(code: string): Finding {
  const has = /"""[\s\S]{20,}"""|docstring|documentation|README/i.test(code) || /technical[-_]?doc/i.test(code);
  return { article: 11, title: 'Technical Documentation', status: has ? 'pass' : 'fail', severity: 'medium',
    description: has ? 'Technical documentation detected' : 'Insufficient technical documentation. EU AI Act requires comprehensive system docs.',
    fix: 'Add docstrings to all agent functions and maintain architecture documentation.' };
}

function checkArticle12(code: string): Finding {
  const has = /(?:audit|log)[-_]?(?:trail|chain|ledger|entry)/i.test(code) || /AuditLedger|HMAC|tamper[-_]?evident/i.test(code) || /logging\.(?:info|warning|error|debug)/i.test(code);
  return { article: 12, title: 'Record-Keeping', status: has ? 'pass' : 'fail', severity: 'critical',
    description: has ? 'Audit logging detected' : 'No tamper-evident logging found. EU AI Act requires automatic event logging.',
    fix: 'Add AIR AuditLedger for HMAC-SHA256 tamper-evident action chains.' };
}

function checkArticle14(code: string): Finding {
  const has = /human[-_]?(?:in[-_]?the[-_]?loop|oversight|approval|confirm|review)/i.test(code) || /ConsentGate|consent[-_]?request|approve|reject/i.test(code) || /input\(|confirm|approval[-_]?required/i.test(code);
  return { article: 14, title: 'Human Oversight', status: has ? 'pass' : 'fail', severity: 'critical',
    description: has ? 'Human oversight mechanism detected' : 'No human oversight found. EU AI Act requires human-in-the-loop for high-risk actions.',
    fix: 'Add AIR ConsentGate to require human approval for critical tool executions.' };
}

function checkArticle15(code: string): Finding {
  const has = /(?:retry|fallback|circuit[-_]?break|error[-_]?hand|try\s*:|except|catch)/i.test(code) || /InjectionDetector|injection[-_]?detect|prompt[-_]?inject/i.test(code);
  return { article: 15, title: 'Accuracy, Robustness & Cybersecurity', status: has ? 'pass' : 'fail', severity: 'high',
    description: has ? 'Robustness measures detected' : 'No cybersecurity measures found. EU AI Act requires protection against adversarial attacks.',
    fix: 'Add AIR InjectionDetector to scan all inputs for prompt injection patterns.' };
}

export function scanCode(code: string): ScanResult {
  const framework = detectFramework(code);
  const hasTrustLayer = detectTrustLayer(code);
  const findings = [checkArticle9(code), checkArticle10(code), checkArticle11(code), checkArticle12(code), checkArticle14(code), checkArticle15(code)];
  const score = findings.filter(f => f.status === 'pass').length;
  return { score, totalArticles: 6, framework, hasTrustLayer, findings };
}