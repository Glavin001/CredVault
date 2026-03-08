import { useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { exportBundle } from "../lib/commands";

interface ExportDialogProps {
  selectedIds: string[];
  onClose: () => void;
}

const FORMAT_EXTENSIONS: Record<string, string> = {
  credvault: ".credvault",
  csv: ".csv",
  env: ".env",
  "agent-config": ".json",
};

export default function ExportDialog({ selectedIds, onClose }: ExportDialogProps) {
  const [format, setFormat] = useState("credvault");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [label, setLabel] = useState("");
  const [expiresHours, setExpiresHours] = useState<string>("");
  const [includeMetadata, setIncludeMetadata] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const needsPassword = format === "credvault";
  const passwordMismatch = needsPassword && password !== confirmPassword && confirmPassword.length > 0;

  async function handleExport() {
    if (needsPassword && password !== confirmPassword) return;
    if (needsPassword && password.length === 0) return;

    setExporting(true);
    setError(null);
    setSuccess(null);

    try {
      const ext = FORMAT_EXTENSIONS[format] ?? "";
      const filePath = await save({
        defaultPath: `credvault-export${ext}`,
        filters: [{ name: format.toUpperCase(), extensions: [ext.replace(".", "")] }],
      });

      if (!filePath) {
        setExporting(false);
        return;
      }

      const result = await exportBundle({
        entry_ids: selectedIds,
        format,
        password: password || "unused",
        label: label || "CredVault Export",
        output_path: filePath,
        expires_hours: expiresHours ? parseInt(expiresHours, 10) : undefined,
        include_metadata: includeMetadata,
      });

      setSuccess(
        `Exported ${selectedIds.length} credentials (${(result.size / 1024).toFixed(1)} KB)`,
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="w-full max-w-md rounded-xl bg-white p-6 shadow-2xl">
        <h3 className="mb-4 text-lg font-semibold text-gray-900">
          Export {selectedIds.length} Credentials
        </h3>

        {success ? (
          <div>
            <div className="rounded-lg border border-green-200 bg-green-50 p-4 text-sm text-green-700">
              {success}
            </div>
            <button
              onClick={onClose}
              className="mt-4 w-full rounded-lg bg-vault-600 py-2 text-sm font-medium text-white hover:bg-vault-700"
            >
              Done
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <label className="mb-1 block text-sm font-medium text-gray-700">Format</label>
              <select
                value={format}
                onChange={(e) => setFormat(e.target.value)}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-vault-500 focus:outline-none focus:ring-1 focus:ring-vault-500"
              >
                <option value="credvault">CredVault (encrypted)</option>
                <option value="csv">CSV (plaintext)</option>
                <option value="env">Environment File</option>
                <option value="agent-config">Agent Config (JSON)</option>
              </select>
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium text-gray-700">Label</label>
              <input
                type="text"
                placeholder="My export"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-vault-500 focus:outline-none focus:ring-1 focus:ring-vault-500"
              />
            </div>

            {needsPassword && (
              <>
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">Password</label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-vault-500 focus:outline-none focus:ring-1 focus:ring-vault-500"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium text-gray-700">
                    Confirm Password
                  </label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className={`w-full rounded-lg border px-3 py-2 text-sm focus:outline-none focus:ring-1 ${
                      passwordMismatch
                        ? "border-red-300 focus:border-red-500 focus:ring-red-500"
                        : "border-gray-300 focus:border-vault-500 focus:ring-vault-500"
                    }`}
                  />
                  {passwordMismatch && (
                    <p className="mt-1 text-xs text-red-500">Passwords do not match</p>
                  )}
                </div>
              </>
            )}

            <div>
              <label className="mb-1 block text-sm font-medium text-gray-700">
                Expires in (hours, optional)
              </label>
              <input
                type="number"
                min="1"
                placeholder="Never"
                value={expiresHours}
                onChange={(e) => setExpiresHours(e.target.value)}
                className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-vault-500 focus:outline-none focus:ring-1 focus:ring-vault-500"
              />
            </div>

            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="metadata"
                checked={includeMetadata}
                onChange={(e) => setIncludeMetadata(e.target.checked)}
                className="rounded border-gray-300"
              />
              <label htmlFor="metadata" className="text-sm text-gray-700">
                Include metadata (timestamps, labels)
              </label>
            </div>

            {error && (
              <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">
                {error}
              </div>
            )}

            <div className="flex gap-3 pt-2">
              <button
                onClick={onClose}
                className="flex-1 rounded-lg border border-gray-300 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleExport}
                disabled={exporting || (needsPassword && (password.length === 0 || passwordMismatch))}
                className="flex-1 rounded-lg bg-vault-600 py-2 text-sm font-medium text-white hover:bg-vault-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {exporting ? "Exporting..." : "Export"}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
