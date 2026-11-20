import { useState } from 'react';
import { AppHeader, type LabTab } from './components/AppHeader';
import { BenchmarksLab } from './features/benchmarks/BenchmarksLab';
import { IngestLab } from './features/ingest/IngestLab';
import { ThreatInspectorLab } from './features/threats/ThreatInspectorLab';

export default function App() {
  const [activeTab, setActiveTab] = useState<LabTab>('ingest');
  return (
    <div className="min-h-screen bg-background">
      <AppHeader activeTab={activeTab} onTabChange={setActiveTab} />
      <main className="workbench-grid min-h-[calc(100vh-70px)] p-3">
        {activeTab === 'ingest' && <IngestLab />}
        {activeTab === 'threats' && <ThreatInspectorLab />}
        {activeTab === 'benchmarks' && <BenchmarksLab />}
      </main>
    </div>
  );
}
