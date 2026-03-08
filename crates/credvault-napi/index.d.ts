export function discoverSourcesJson(fixturesDir: string): string;
export function listCredentialsJson(fixturesDir: string, filterJson?: string | null): string;
export function exportAgentConfigJson(
  fixturesDir: string,
  entryIdsJson: string,
  label: string
): string;
export function readBundleJson(bundleBytes: Uint8Array, password: string): string;
