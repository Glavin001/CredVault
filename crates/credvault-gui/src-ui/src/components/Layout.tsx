import { ReactNode } from "react";

type Tab = "sources" | "credentials" | "import";

interface LayoutProps {
  activeTab: Tab;
  onTabChange: (tab: Tab) => void;
  children: ReactNode;
}

const tabs: { id: Tab; label: string }[] = [
  { id: "sources", label: "Sources" },
  { id: "credentials", label: "Credentials" },
  { id: "import", label: "Import Bundle" },
];

export default function Layout({ activeTab, onTabChange, children }: LayoutProps) {
  return (
    <div className="flex h-screen flex-col">
      {/* Title bar */}
      <header className="flex items-center justify-between border-b border-gray-200 bg-white px-6 py-3">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-vault-600 text-sm font-bold text-white">
            CV
          </div>
          <h1 className="text-lg font-semibold text-gray-900">CredVault</h1>
        </div>
        <span className="text-xs text-gray-400">v0.1.0</span>
      </header>

      {/* Tab navigation */}
      <nav className="flex border-b border-gray-200 bg-white px-6">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id)}
            className={`-mb-px border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? "border-vault-600 text-vault-700"
                : "border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* Content */}
      <main className="flex-1 overflow-auto p-6">{children}</main>
    </div>
  );
}
