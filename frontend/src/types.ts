// Types mirror the gateway's JSON surface (research/l0/api.go).

export interface OrgSummary {
  id: string;
  name: string;
  created: number;
  events: number;
  detected: boolean;
}

export interface OrgDetail {
  id: string;
  name: string;
  created: number;
  detected: boolean;
}

export interface TimelineEvent {
  type: string;
  ts: number;
  cert_id?: string;
  identity?: string;
  via?: string;
  hash: string;
}

export interface CertState {
  Identity: string;
  Revoked: boolean;
}

export interface TrustState {
  certs: Record<string, CertState>;
}

export interface UserRow {
  id: string;
  role: string;
  orgs: string[] | null;
  tokens: number;
}

export interface WebhookRow {
  ID: string;
  URL: string;
  Events: string[] | null;
  Active: boolean;
}

export interface AuditEvent extends TimelineEvent {
  org: string;
}

export interface STH {
  org: string;
  log_key_hex: string;
  tree_size: number;
  timestamp: number;
  root_hex: string;
  signature_hex: string;
}

export interface InclusionProof {
  org: string;
  index: number;
  size: number;
  leaf_hash_hex: string;
  root_hex: string;
  proof: string[];
}

export interface ConsistencyProof {
  org: string;
  from: number;
  to: number;
  old_root_hex: string;
  new_root_hex: string;
  proof: string[];
}

export interface BackupInfo {
  id: string;
  size: number;
  download: string;
}