// Typed wrappers over the Tauri command/event surface (src-tauri/src/commands.rs).

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export interface ProxyStatus {
  running: boolean;
  port: number;
  baseUrl: string;
  apiKeyPresent: boolean;
  activeRequests: number;
  totalRequests: number;
  totalPromptTokens: number;
  totalCompletionTokens: number;
  version: string;
}

export interface ApiKeyStatus {
  present: boolean;
  masked: string | null;
}

export interface ModelInfo {
  id: string;
  label: string;
  model: string;
  baseUrl: string;
}

export interface VerificationCheck {
  id: string;
  label: string;
  status: string;
  ok: boolean;
}

export interface AttestationSummary {
  model_id: string;
  base_url: string;
  provider: string;
  verified: boolean;
  model_pubkey_hex?: string;
  tls_fingerprint?: string;
  /** Ordered provider-specific checks; empty when verification failed before any ran. */
  checks: VerificationCheck[];
  error?: string;
}

export type RequestTerminalStatus = "completed" | "failed" | "cancelled";

/** Metadata proving which encrypted request path was used; never message content. */
export interface E2eeAuditReceipt {
  protocol?: string;
  encryption_version?: number;
  request_encrypted: boolean;
  backend_key_accepted: boolean;
  response_decrypted: boolean;
  ephemeral_client_key: boolean;
}

/** Metadata from the locally verified attestation used by a request; key material is a fingerprint only. */
export interface TeeAuditReceipt {
  verified: boolean;
  verified_at_unix_ms?: number;
  age_ms?: number;
  model_key_sha256?: string;
  tls_spki_sha256?: string;
  checks: VerificationCheck[];
}

/** Metadata-only request-log entry (never message content). */
export interface RequestLogEntry {
  id: string;
  model: string;
  provider: string;
  stream: boolean;
  status: RequestTerminalStatus;
  started_at_unix_ms: number;
  completed_at_unix_ms: number;
  prompt_tokens: number;
  completion_tokens: number;
  duration_ms: number;
  finish_reason?: string;
  error_kind?: string;
  e2ee: E2eeAuditReceipt;
  tee: TeeAuditReceipt;
}

/** `true` only when the request reached a valid encrypted terminal completion; mirrors the Rust-side check. */
export function isFullyVerified(entry: RequestLogEntry): boolean {
  return (
    entry.status === "completed" &&
    entry.tee.verified &&
    entry.e2ee.request_encrypted &&
    entry.e2ee.backend_key_accepted &&
    entry.e2ee.response_decrypted &&
    entry.e2ee.ephemeral_client_key &&
    entry.e2ee.protocol === "near-v2" &&
    entry.e2ee.encryption_version === 2
  );
}

export interface ProxyConfig {
  port: number;
  backend_url: string;
  attestation_ttl_secs: number;
  default_model: string | null;
  start_minimized: boolean;
  close_to_tray: boolean;
  log_level: string;
}

export const api = {
  getStatus: () => invoke<ProxyStatus>("get_status"),
  startServer: () => invoke<ProxyStatus>("start_server"),
  stopServer: () => invoke<ProxyStatus>("stop_server"),
  getConfig: () => invoke<ProxyConfig>("get_config"),
  setConfig: (patch: Partial<ProxyConfig>) => invoke<ProxyConfig>("set_config", { patch }),
  setApiKey: (key: string) => invoke<ApiKeyStatus>("set_api_key", { key }),
  clearApiKey: () => invoke<void>("clear_api_key"),
  getApiKeyStatus: () => invoke<ApiKeyStatus>("get_api_key_status"),
  listModels: () => invoke<ModelInfo[]>("list_models"),
  verifyModel: (modelId: string, force: boolean) =>
    invoke<AttestationSummary>("verify_model", { modelId, force }),
  getAttestations: () => invoke<AttestationSummary[]>("get_attestations"),
  getRecentRequests: (limit: number) => invoke<RequestLogEntry[]>("get_recent_requests", { limit }),
};

export function onStatus(cb: (s: ProxyStatus) => void): Promise<UnlistenFn> {
  return listen<ProxyStatus>("proxy://status", (e) => cb(e.payload));
}

export function onAttestation(cb: (s: AttestationSummary) => void): Promise<UnlistenFn> {
  return listen<AttestationSummary>("proxy://attestation", (e) => cb(e.payload));
}
