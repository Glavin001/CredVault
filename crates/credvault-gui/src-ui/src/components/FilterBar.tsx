import { FilterParams } from "../lib/commands";

interface FilterBarProps {
  filter: FilterParams;
  onChange: (filter: FilterParams) => void;
}

export default function FilterBar({ filter, onChange }: FilterBarProps) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      <div className="flex-1">
        <input
          type="text"
          placeholder="Search domains, usernames..."
          value={filter.search ?? ""}
          onChange={(e) =>
            onChange({ ...filter, search: e.target.value || undefined })
          }
          className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm placeholder-gray-400 focus:border-vault-500 focus:outline-none focus:ring-1 focus:ring-vault-500"
        />
      </div>

      <select
        value={filter.types?.[0] ?? ""}
        onChange={(e) =>
          onChange({
            ...filter,
            types: e.target.value ? [e.target.value] : undefined,
          })
        }
        className="rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-700 focus:border-vault-500 focus:outline-none focus:ring-1 focus:ring-vault-500"
      >
        <option value="">All Types</option>
        <option value="Password">Passwords</option>
        <option value="CreditCard">Credit Cards</option>
        <option value="Cookie">Cookies</option>
        <option value="ApiKey">API Keys</option>
        <option value="Certificate">Certificates</option>
        <option value="SessionToken">Session Tokens</option>
      </select>
    </div>
  );
}
