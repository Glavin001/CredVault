import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { readBundle, BundleContents } from "../lib/commands";

export default function ImportDialog() {
  const [password, setPassword] = useState("");
  const [filePath, setFilePath] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [contents, setContents] = useState<BundleContents | null>(null);

  async function selectFile() {
    const path = await open({
      multiple: false,
      filters: [
        { name: "CredVault Bundle", extensions: ["credvault"] },
        { name: "All Files", extensions: ["*"] },
      ],
    });
    if (path) {
      setFilePath(path as string);
      setContents(null);
      setError(null);
    }
  }

  async function handleRead() {
    if (!filePath || !password) return;
    setLoading(true);
    setError(null);

    try {
      const result = await readBundle(filePath, password);
      setContents(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <h2 className="mb-4 text-lg font-semibold text-gray-900">Import Bundle</h2>

      <div className="mx-auto max-w-lg space-y-4">
        {/* File selection */}
        <div>
          <label className="mb-1 block text-sm font-medium text-gray-700">Bundle File</label>
          <div className="flex gap-2">
            <input
              type="text"
              readOnly
              value={filePath ?? ""}
              placeholder="No file selected"
              className="flex-1 rounded-lg border border-gray-300 bg-gray-50 px-3 py-2 text-sm text-gray-500"
            />
            <button
              onClick={selectFile}
              className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Browse
            </button>
          </div>
        </div>

        {/* Password */}
        <div>
          <label className="mb-1 block text-sm font-medium text-gray-700">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-vault-500 focus:outline-none focus:ring-1 focus:ring-vault-500"
          />
        </div>

        <button
          onClick={handleRead}
          disabled={!filePath || !password || loading}
          className="w-full rounded-lg bg-vault-600 py-2 text-sm font-medium text-white hover:bg-vault-700 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? "Decrypting..." : "Decrypt & Read"}
        </button>

        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">
            {error}
          </div>
        )}

        {/* Bundle contents */}
        {contents && (
          <div className="mt-6 rounded-lg border border-gray-200 bg-white">
            <div className="border-b border-gray-200 px-4 py-3">
              <h3 className="font-medium text-gray-900">{contents.label}</h3>
              <div className="mt-1 flex gap-4 text-xs text-gray-500">
                <span>Created: {new Date(contents.created).toLocaleString()}</span>
                {contents.expires && (
                  <span>Expires: {new Date(contents.expires).toLocaleString()}</span>
                )}
                <span>ID: {contents.bundle_id.slice(0, 8)}...</span>
              </div>
            </div>

            <table className="min-w-full divide-y divide-gray-100">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-2 text-left text-xs font-medium uppercase text-gray-500">
                    Domain
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium uppercase text-gray-500">
                    Username
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium uppercase text-gray-500">
                    Password
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-medium uppercase text-gray-500">
                    Type
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {contents.credentials.map((cred, i) => (
                  <tr key={i}>
                    <td className="px-4 py-2 text-sm font-medium text-gray-900">
                      {cred.domain}
                    </td>
                    <td className="px-4 py-2 text-sm text-gray-700">
                      {cred.username ?? "\u2014"}
                    </td>
                    <td className="px-4 py-2">
                      <PasswordCell password={cred.password} />
                    </td>
                    <td className="px-4 py-2 text-xs text-gray-500">{cred.credential_type}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function PasswordCell({ password }: { password: string }) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="flex items-center gap-2">
      <span className="font-mono text-sm">
        {visible ? password : "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"}
      </span>
      <button
        onClick={() => setVisible(!visible)}
        className="text-xs text-vault-600 hover:text-vault-800"
      >
        {visible ? "Hide" : "Show"}
      </button>
    </div>
  );
}
