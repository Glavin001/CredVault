import { useEffect, useState, useCallback } from "react";
import {
  CredentialEntry,
  FilterParams,
  listCredentials,
  ListResult,
} from "../lib/commands";
import FilterBar from "./FilterBar";
import ExportDialog from "./ExportDialog";

interface CredentialTableProps {
  initialSourceFilter?: string;
}

export default function CredentialTable({ initialSourceFilter }: CredentialTableProps) {
  const [result, setResult] = useState<ListResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<FilterParams>(
    initialSourceFilter ? { sources: [initialSourceFilter] } : {},
  );
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [showExport, setShowExport] = useState(false);

  const loadCredentials = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listCredentials(
        Object.keys(filter).length > 0 ? filter : undefined,
      );
      setResult(data);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    loadCredentials();
  }, [loadCredentials]);

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    if (!result) return;
    if (selected.size === result.entries.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(result.entries.map((e) => e.id)));
    }
  }

  function credentialTypeBadge(ct: string) {
    const colors: Record<string, string> = {
      Password: "bg-blue-100 text-blue-700",
      CreditCard: "bg-purple-100 text-purple-700",
      Cookie: "bg-amber-100 text-amber-700",
      ApiKey: "bg-emerald-100 text-emerald-700",
      Certificate: "bg-cyan-100 text-cyan-700",
      SessionToken: "bg-pink-100 text-pink-700",
    };
    return (
      <span
        className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${colors[ct] ?? "bg-gray-100 text-gray-600"}`}
      >
        {ct}
      </span>
    );
  }

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-gray-900">
          Credentials
          {result && (
            <span className="ml-2 text-sm font-normal text-gray-400">
              ({result.entries.length}
              {result.duplicate_count > 0 &&
                `, ${result.duplicate_count} duplicate groups`}
              )
            </span>
          )}
        </h2>
        <div className="flex items-center gap-2">
          {selected.size > 0 && (
            <button
              onClick={() => setShowExport(true)}
              className="rounded-lg bg-vault-600 px-4 py-2 text-sm font-medium text-white hover:bg-vault-700"
            >
              Export ({selected.size})
            </button>
          )}
          <button
            onClick={loadCredentials}
            className="rounded-lg border border-gray-300 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
          >
            Refresh
          </button>
        </div>
      </div>

      <div className="mb-4">
        <FilterBar filter={filter} onChange={setFilter} />
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="mx-auto h-8 w-8 animate-spin rounded-full border-4 border-vault-200 border-t-vault-600" />
        </div>
      ) : error ? (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4">
          <p className="text-sm text-red-800">{error}</p>
        </div>
      ) : result && result.entries.length === 0 ? (
        <div className="py-20 text-center text-gray-500">
          No credentials found matching the current filters.
        </div>
      ) : result ? (
        <div className="overflow-hidden rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="w-10 px-4 py-3">
                  <input
                    type="checkbox"
                    checked={selected.size === result.entries.length && result.entries.length > 0}
                    onChange={toggleAll}
                    className="rounded border-gray-300"
                  />
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                  Domain
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                  Username
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                  Type
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                  Source
                </th>
                <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500">
                  Modified
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {result.entries.map((entry: CredentialEntry) => (
                <tr
                  key={entry.id}
                  className={`cursor-pointer transition-colors hover:bg-gray-50 ${selected.has(entry.id) ? "bg-vault-50" : ""}`}
                  onClick={() => toggleSelect(entry.id)}
                >
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      checked={selected.has(entry.id)}
                      onChange={() => toggleSelect(entry.id)}
                      onClick={(e) => e.stopPropagation()}
                      className="rounded border-gray-300"
                    />
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-medium text-gray-900">{entry.domain}</div>
                    {entry.url && (
                      <div className="truncate text-xs text-gray-400" style={{ maxWidth: 250 }}>
                        {entry.url}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-700">
                    {entry.username ?? <span className="text-gray-300">&mdash;</span>}
                  </td>
                  <td className="px-4 py-3">{credentialTypeBadge(entry.credential_type)}</td>
                  <td className="px-4 py-3 text-sm text-gray-500">{entry.source_id}</td>
                  <td className="px-4 py-3 text-sm text-gray-400">
                    {entry.modified
                      ? new Date(entry.modified).toLocaleDateString()
                      : "\u2014"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {showExport && (
        <ExportDialog
          selectedIds={Array.from(selected)}
          onClose={() => setShowExport(false)}
        />
      )}
    </div>
  );
}
