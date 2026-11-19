/**
 * Headroom Shield — Zero-Dependency TypeScript/JavaScript ESM SDK
 * Portable browser, Node.js, Deno, Bun & Cloudflare Workers compression + Stage-0 Security Shield.
 * API inspired by headroomlabs-ai/headroom TypeScript SDK (mapped via REA static analysis).
 */

const INVISIBLE_RX = /[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g;
const MD_EXFIL_RX = /!\[[^\]]*\]\((https?:\/\/[^)\s]+)\)/gi;
const INJECTION_RX = /<IMPORTANT>[\s\S]*?<\/IMPORTANT>|(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions|prompts|rules)/gi;
const ERROR_RX = /\b(?:fatal|error|critical|exception|traceback|panic|failed|denied|timeout|5\d\d|403|401)\b/i;
const LOG_VAR_RX = /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b0x[0-9a-fA-F]+\b|\b\d+\b/g;

const PII_PATTERNS = [
  ['GOOGLE_API_KEY', /\bAIza[0-9A-Za-z\-_]{35}\b/g],
  ['AWS_ACCESS_KEY', /\bAKIA[0-9A-Z]{16}\b/g],
  ['GITHUB_PAT', /\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b/g],
  ['JWT_TOKEN', /\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b/g],
  ['CNPJ', /\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/g],
  ['CPF', /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g],
  ['EMAIL', /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g],
  ['IPV4_INTERNAL', /\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[0-1]))\.\d{1,3}\.\d{1,3}\b/g]
];

export const estimateTokens = (text) => (text ? Math.max(1, Math.ceil(text.length / 3.8)) : 0);

function shortHash(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193); }
  return ((h >>> 0).toString(16).padStart(8, '0') + str.length.toString(16).padStart(4, '0')).slice(0, 12);
}

export class MemoryCCRStore {
  constructor() { this.map = new Map(); }
  store(payload, meta = {}) {
    const raw = typeof payload === 'string' ? payload : JSON.stringify(payload);
    const id = shortHash(raw);
    this.map.set(id, { hash: id, content: raw, meta, createdAt: Date.now() });
    return id;
  }
  retrieve(id) { return this.map.get(id) || null; }
}

export function applySecurityShield(text, { redactPii = true, neutralizeInjections = true } = {}) {
  let clean = text;
  const threats = [];
  const tokenToRaw = new Map(), rawToToken = new Map(), counts = {};

  const inv = clean.match(INVISIBLE_RX);
  if (inv) { clean = clean.replace(INVISIBLE_RX, ''); threats.push({ owasp: 'LLM01', rule: `Stripped ${inv.length} invisible Unicode/BiDi chars` }); }
  if (neutralizeInjections) {
    if (MD_EXFIL_RX.test(clean)) { clean = clean.replace(MD_EXFIL_RX, '[BLOCKED_EXTERNAL_MD_IMAGE]'); threats.push({ owasp: 'LLM02', rule: 'Blocked Markdown Image Exfiltration' }); }
    if (INJECTION_RX.test(clean)) { clean = clean.replace(INJECTION_RX, '[NEUTRALIZED_LLM01_INJECTION]'); threats.push({ owasp: 'LLM01', rule: 'Neutralized Indirect Prompt Injection' }); }
  }
  if (redactPii) {
    for (const [type, rx] of PII_PATTERNS) {
      clean = clean.replace(rx, (m) => {
        let tok = rawToToken.get(m);
        if (!tok) { counts[type] = (counts[type] || 0) + 1; tok = `<${type}_${counts[type]}>`; rawToToken.set(m, tok); tokenToRaw.set(tok, m); }
        return tok;
      });
    }
  }
  return {
    sanitized: clean,
    threats,
    redactedCount: tokenToRaw.size,
    vault: tokenToRaw,
    rehydrate(reply) { let out = reply; for (const [t, r] of tokenToRaw.entries()) out = out.replaceAll(t, r); return out; }
  };
}

export function compress(text, { store = new MemoryCCRStore(), securityShield = true, redactPii = true, csvSchema = false } = {}) {
  const tokensBefore = estimateTokens(text);
  const audit = securityShield ? applySecurityShield(text, { redactPii }) : { sanitized: text, threats: [], redactedCount: 0, vault: new Map(), rehydrate: (s) => s };
  const work = audit.sanitized.trim();
  let out = work, ccrHash = null, strategy = 'passthrough', contentType = 'text';

  // 1) JSON SmartCrusher
  if ((work.startsWith('[') && work.endsWith(']')) || (work.startsWith('{') && work.endsWith('}'))) {
    try {
      const parsed = JSON.parse(work);
      contentType = 'json';
      if (Array.isArray(parsed) && parsed.length > 7) {
        const keep = new Set([0, 1, 2, parsed.length - 2, parsed.length - 1]);
        parsed.forEach((item, idx) => {
          const s = JSON.stringify(item);
          if (ERROR_RX.test(s) || (item && typeof item === 'object' && ((item.status >= 400) || (item.status_code >= 400)))) keep.add(idx);
        });
        const dropped = parsed.length - keep.size;
        if (dropped > 0) {
          ccrHash = store.store(parsed, { type: 'json_array', total: parsed.length, dropped });
          const kept = [...keep].sort((a, b) => a - b).map((i) => parsed[i]);
          if (csvSchema && kept.every((x) => x && typeof x === 'object' && !Array.isArray(x))) {
            const keys = Object.keys(kept[0]);
            out = `# CSV-Schema Compact (${kept.length}/${parsed.length} rows | ${dropped} offloaded <<ccr:${ccrHash}>>)\n${keys.join(',')}\n` + kept.map((r) => keys.map((k) => r[k] ?? '').join(',')).join('\n');
            strategy = 'smart-crusher-csv-schema';
          } else {
            kept.splice(3, 0, { _ccr_dropped: `<<ccr:${ccrHash} ${dropped}_rows_offloaded_of_${parsed.length}>>` });
            out = JSON.stringify(kept);
            strategy = 'smart-crusher-statistical';
          }
        }
      } else {
        out = JSON.stringify(parsed);
        strategy = 'json-minified';
      }
    } catch {}
  }

  // 2) Log Deduplicator
  if (contentType === 'text') {
    const lines = work.split(/\r?\n/);
    if (lines.length > 20 && lines.slice(0, 30).filter((l) => /\b(INFO|DEBUG|WARN|ERROR|FATAL)\b|\d{4}-\d{2}-\d{2}/.test(l)).length >= 3) {
      contentType = 'log';
      const seen = new Set(), kept = [], counts = {};
      let dropped = 0;
      lines.forEach((l, i) => {
        const s = l.trim(); if (!s) return;
        if (i < 4 || i >= lines.length - 4 || ERROR_RX.test(s)) { kept.push(l); return; }
        const tmpl = s.replace(LOG_VAR_RX, '<*>');
        counts[tmpl] = (counts[tmpl] || 0) + 1;
        if (!seen.has(tmpl)) { seen.add(tmpl); kept.push(l); } else dropped++;
      });
      if (dropped > 0) {
        ccrHash = store.store(work, { type: 'logs', totalLines: lines.length, dropped });
        out = `[LOG_SUMMARY: ${lines.length} -> ${kept.length} lines | ${dropped} repetitive lines offloaded <<ccr:${ccrHash}>>]\n` + kept.join('\n');
        strategy = 'log-template-dedup';
      }
    }
  }

  const tokensAfter = estimateTokens(out);
  const savingsPercent = Number(Math.max(0, (1 - tokensAfter / Math.max(1, tokensBefore)) * 100).toFixed(2));
  return { content: out, contentType, strategy, tokensBefore, tokensAfter, savingsPercent, ccrHash, threats: audit.threats, redactedCount: audit.redactedCount, audit };
}
