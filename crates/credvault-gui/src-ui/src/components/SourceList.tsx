import { useEffect, useState } from "react";
import { CredentialSource, discoverSources, SourceType } from "../lib/commands";

function sourceTypeLabel(st: SourceType): string {
  if (typeof st === "string") return "OS Keychain";
  if ("Browser" in st) return st.Browser;
  if ("PasswordManager" in st) return st.PasswordManager;
  return "Unknown";
}

function statusBadge(status: string) {
  const styles: Record<string, string> = {
    Accessible: "bg-green-100 text-green-700",
    Locked: "bg-yellow-100 text-yellow-700",
    RequiresAuth: "bg-orange-100 text-orange-700",
    NotFound: "bg-gray-100 text-gray-500",
  };
  return (
    <span
      className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium ${styles[status] ?? "bg-gray-100 text-gray-500"}`}
    >
      {status}
    </span>
  );
}

interface SourceListProps {
  onSelectSource: (sourceId: string) => void;
}

export default function SourceList({ onSelectSource }: SourceListProps) {
  const [sources, setSources] = useState<CredentialSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadSources();
  }, []);

  async function loadSources() {
    setLoading(true);
    setError(null);
    try {
      const result = await discoverSources();
      setSources(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-center">
          <div className="mx-auto mb-3 h-8 w-8 animate-spin rounded-full border-4 border-vault-200 border-t-vault-600" />
          <p className="text-sm text-gray-500">Scanning for credential sources...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-4">
        <p className="text-sm font-medium text-red-800">Failed to scan sources</p>
        <p className="mt-1 text-sm text-red-600">{error}</p>
        <button
          onClick={loadSources}
          className="mt-3 rounded bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700"
        >
          Retry
        </button>
      </div>
    );
  }

  if (sources.length === 0) {
    return (
      <div className="py-20 text-center">
        <p className="text-gray-500">No credential sources found on this system.</p>
        <button
          onClick={loadSources}
          className="mt-4 rounded-lg bg-vault-600 px-4 py-2 text-sm font-medium text-white hover:bg-vault-700"
        >
          Rescan
        </button>
      </div>
    );
  }

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-900">
          Credential Sources
          <span className="ml-2 text-sm font-normal text-gray-400">({sources.length})</span>
        </h2>
        <button
          onClick={loadSources}
          className="rounded-lg border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50"
        >
          Rescan
        </button>
      </div>

      <div className="grid gap-3">
        {sources.map((source) => (
          <div
            key={source.id}
            className="group flex cursor-pointer items-center justify-between rounded-lg border border-gray-200 bg-white p-4 transition-shadow hover:shadow-md"
            onClick={() => source.status === "Accessible" && onSelectSource(source.id)}
          >
            <div className="flex items-center gap-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-vault-50 text-lg">
                {typeof source.source_type !== "string" && "Browser" in source.source_type
                  ? "\uD83C\uDF10"
                  : "\uD83D\uDD11"}
              </div>
              <div>
                <p className="font-medium text-gray-900">{source.name}</p>
                <p className="text-sm text-gray-500">
                  {sourceTypeLabel(source.source_type)}
                  {source.credential_count != null && (
                    <span className="ml-2">
                      &middot; {source.credential_count} credentials
                    </span>
                  )}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {statusBadge(source.status)}
              {source.status === "Accessible" && (
                <svg
                  className="h-5 w-5 text-gray-400 group-hover:text-vault-600"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={2}
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                </svg>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
