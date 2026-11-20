export interface ThreatRecord {
  owasp: string;
  rule: string;
}

export interface SecurityAuditResult {
  sanitized: string;
  threats: ThreatRecord[];
  redactedCount: number;
  vault: Map<string, string>;
  rehydrate(reply: string): string;
}

export interface CompressOptions {
  store?: MemoryCCRStore;
  securityShield?: boolean;
  redactPii?: boolean;
  csvSchema?: boolean;
}

export interface CompressResult {
  content: string;
  contentType: 'json' | 'log' | 'text';
  strategy: string;
  tokensBefore: number;
  tokensAfter: number;
  savingsPercent: number;
  ccrHash: string | null;
  threats: ThreatRecord[];
  redactedCount: number;
  audit: SecurityAuditResult;
}

export declare class MemoryCCRStore {
  store(payload: unknown, meta?: Record<string, unknown>): string;
  retrieve(id: string): { hash: string; content: string; meta: Record<string, unknown>; createdAt: number } | null;
}

export declare function estimateTokens(text: string): number;
export declare function applySecurityShield(text: string, opts?: { redactPii?: boolean; neutralizeInjections?: boolean }): SecurityAuditResult;
export declare function compress(text: string, opts?: CompressOptions): CompressResult;
