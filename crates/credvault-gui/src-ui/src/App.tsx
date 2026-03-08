import { useState } from "react";
import Layout from "./components/Layout";
import SourceList from "./components/SourceList";
import CredentialTable from "./components/CredentialTable";
import ImportDialog from "./components/ImportDialog";

type Tab = "sources" | "credentials" | "import";

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("sources");
  const [sourceFilter, setSourceFilter] = useState<string | undefined>();

  function handleSelectSource(sourceId: string) {
    setSourceFilter(sourceId);
    setActiveTab("credentials");
  }

  function handleTabChange(tab: Tab) {
    if (tab === "credentials") {
      setSourceFilter(undefined);
    }
    setActiveTab(tab);
  }

  return (
    <Layout activeTab={activeTab} onTabChange={handleTabChange}>
      {activeTab === "sources" && <SourceList onSelectSource={handleSelectSource} />}
      {activeTab === "credentials" && (
        <CredentialTable initialSourceFilter={sourceFilter} />
      )}
      {activeTab === "import" && <ImportDialog />}
    </Layout>
  );
}
