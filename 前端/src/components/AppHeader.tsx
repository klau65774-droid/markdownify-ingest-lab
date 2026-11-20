import { useEffect, useState } from 'react';
import { Activity, ShieldCheck } from 'lucide-react';
import { api } from '../api/client';

export type LabTab = 'ingest' | 'threats' | 'benchmarks';

const TABS = [
  { id: 'ingest' as const, number: '01', label: 'HTML-to-Markdown', sublabel: '& Sanitizer Diff' },
  { id: 'threats' as const, number: '02', label: 'Indirect Prompt-', sublabel: 'Injection Inspector' },
  { id: 'benchmarks' as const, number: '03', label: 'Web Extraction &', sublabel: 'BIPIA Benchmarks' },
];

type HealthState =
  | { status: 'checking'; message?: string }
  | { status: 'online'; latency: number }
  | { status: 'offline'; message: string };

type AppHeaderProps = {
  activeTab: LabTab;
  onTabChange: (tab: LabTab) => void;
};

export function AppHeader({ activeTab, onTabChange }: AppHeaderProps) {
  const [health, setHealth] = useState<HealthState>({ status: 'checking' });

  useEffect(() => {
    let mounted = true;
    const checkHealth = async () => {
      try {
        const result = await api.health();
        if (mounted) setHealth({ status: 'online', latency: result.latencyMs });
      } catch (error) {
        if (mounted) {
          setHealth({
            status: 'offline',
            message: error instanceof Error ? error.message : 'Unknown connection error',
          });
        }
      }
    };
    void checkHealth();
    const timer = window.setInterval(() => void checkHealth(), 15_000);
    return () => {
      mounted = false;
      window.clearInterval(timer);
    };
  }, []);

  return (
    <header className="relative z-20 flex min-h-[70px] flex-wrap items-stretch border-b border-border bg-[#0a1019]/95 shadow-[0_8px_30px_rgba(0,0,0,0.25)] xl:flex-nowrap">
      <div className="flex w-full min-w-0 flex-none items-center gap-3 px-4 py-3 sm:w-auto sm:flex-1 xl:w-[420px] xl:flex-none 2xl:w-[470px]">
        <div className="relative grid h-8 w-8 flex-none place-items-center border border-cyan/40 bg-cyan/5 text-cyan shadow-[inset_0_0_14px_rgba(6,182,212,0.08)]">
          <ShieldCheck size={20} strokeWidth={1.5} aria-hidden="true" />
          <span className="absolute -right-1 -top-1 h-2 w-2 bg-cyan" />
        </div>
        <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
          <h1 className="whitespace-nowrap text-[13px] font-semibold tracking-[0.04em] text-slate-100">
            <span className="text-slate-200">MARKDOWNIFY</span>
            <span className="mx-1.5 text-slate-600">//</span>
            <span className="font-normal text-slate-400">INGEST LAB</span>
          </h1>
          <span className="rounded border border-cyan/35 bg-cyan/5 px-1.5 py-0.5 font-mono text-[8px] tracking-tight text-cyan">
            v1.2.4 + DOM Prompt Guard
          </span>
        </div>
      </div>

      <nav aria-label="Laboratory views" className="order-3 grid w-full grid-cols-3 border-t border-border xl:order-none xl:w-auto xl:flex-1 xl:border-t-0">
        {TABS.map((tab) => {
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              aria-label={`${tab.number} ${tab.label}${tab.sublabel}`}
              aria-pressed={active}
              onClick={() => onTabChange(tab.id)}
              className={`group relative flex min-w-0 items-center justify-center gap-2.5 px-2 py-2.5 text-left transition-colors duration-200 xl:py-0 ${
                active
                  ? 'bg-gradient-to-b from-cyan/[0.04] to-cyan/[0.12] text-slate-100'
                  : 'text-slate-500 hover:bg-white/[0.02] hover:text-slate-300'
              }`}
            >
              <span className={`font-mono text-[17px] font-medium ${active ? 'text-cyan' : 'text-slate-600 group-hover:text-slate-500'}`}>
                {tab.number}
              </span>
              <span className="min-w-0 text-[10px] font-medium leading-[1.35] tracking-[0.01em] sm:text-[11px]">
                <span className="block truncate">{tab.label}</span>
                <span className="block truncate">{tab.sublabel}</span>
              </span>
              {active && <span className="absolute inset-x-0 bottom-0 h-0.5 bg-cyan shadow-[0_0_12px_rgba(6,182,212,0.65)]" />}
            </button>
          );
        })}
      </nav>

      <div className="order-2 flex w-full items-center justify-center border-t border-border/70 px-4 py-3 sm:w-auto sm:justify-end sm:border-t-0 xl:order-none xl:w-[280px] xl:flex-none 2xl:w-[300px]">
        {health.status === 'online' ? (
          <div className="flex items-center gap-2 rounded-full border border-emerald/20 bg-emerald/[0.06] px-3 py-1.5 text-[9px] shadow-[0_0_20px_rgba(16,185,129,0.05)]">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald opacity-50" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald" />
            </span>
            <span className="font-medium tracking-[0.05em] text-slate-400">INGEST ENGINE</span>
            <span className="font-semibold tracking-[0.04em] text-emerald">ONLINE</span>
            <span className="text-slate-600">·</span>
            <span className="font-mono text-slate-400">{health.latency.toFixed(2)} ms CPU</span>
          </div>
        ) : (
          <div className="flex items-center gap-2 rounded-full border border-border bg-raised/60 px-3 py-1.5 text-[9px]">
            <Activity size={11} className={health.status === 'offline' ? 'text-rose' : 'animate-pulse text-amber'} aria-hidden="true" />
            {health.status === 'offline' ? (
              <span title={health.message} className="font-semibold tracking-[0.06em] text-rose">ENGINE OFFLINE</span>
            ) : (
              <span className="font-medium tracking-[0.06em] text-amber">CHECKING ENGINE</span>
            )}
          </div>
        )}
      </div>
    </header>
  );
}
