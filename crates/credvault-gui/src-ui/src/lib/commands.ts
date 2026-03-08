import { invoke } from "@tauri-apps/api/core";

// ── Types matching Rust structs ──────────────────────────────

export interface CredentialSource {
  id: string;
  name: string;
  source_type: SourceType;
  platform: string;
  status: string;
  credential_count: number | null;
  profiles: Profile[];
}

export type SourceType =
  | { Browser: string }
  | "OsKeychain"
  | { PasswordManager: string };

export interface Profile {
  id: string;
  name: string;
  path: string;
}

export interface CredentialEntry {
  id: string;
  source_id: string;
  credential_type: string;
  domain: string;
  url: string | null;
  username: string | null;
  label: string | null;
  created: string | null;
  last_used: string | null;
  modified: string | null;
}

export interface ListResult {
  entries: CredentialEntry[];
  sources_scanned: string[];
  duplicate_count: number;
}

export interface ExtractedCredential {
  id: string;
  source_id: string;
  credential_type: string;
  domain: string;
  url: string | null;
  username: string | null;
  label: string | null;
  secret: string;
}

export interface FilterParams {
  domains?: string[];
  sources?: string[];
  types?: string[];
  search?: string;
}

export interface ExportParams {
  entry_ids: string[];
  format: string;
  password: string;
  label: string;
  output_path: string;
  expires_hours?: number;
  include_metadata: boolean;
}

export interface ExportResult {
  path: string;
  size: number;
}

export interface BundleContents {
  label: string;
  created: string;
  expires: string | null;
  bundle_id: string;
  credentials: BundleCredential[];
}

export interface BundleCredential {
  domain: string;
  url: string | null;
  username: string | null;
  password: string;
  credential_type: string;
  label: string | null;
}

// ── Command wrappers ─────────────────────────────────────────

export async function discoverSources(): Promise<CredentialSource[]> {
  return invoke<CredentialSource[]>("discover_sources");
}

export async function listCredentials(
  filter?: FilterParams,
): Promise<ListResult> {
  return invoke<ListResult>("list_credentials", { filter: filter ?? null });
}

export async function extractCredentials(
  entryIds: string[],
): Promise<ExtractedCredential[]> {
  return invoke<ExtractedCredential[]>("extract_credentials", {
    entryIds,
  });
}

export async function exportBundle(
  params: ExportParams,
): Promise<ExportResult> {
  return invoke<ExportResult>("export_bundle", { params });
}

export async function readBundle(
  path: string,
  password: string,
): Promise<BundleContents> {
  return invoke<BundleContents>("read_bundle", {
    params: { path, password },
  });
}
