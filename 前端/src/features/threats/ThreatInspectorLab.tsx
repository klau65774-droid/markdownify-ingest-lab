import { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowRight, Braces, CheckCircle2, Clock3, Crosshair, Layers3, ScanSearch, ShieldAlert, ShieldCheck, Table2 } from 'lucide-react';
import { api } from '../../api/client';
import type { Preset, Severity, TableNormalizeResult, ThreatInspectResult } from '../../api/types';
import { CodeView, HtmlEditor } from '../../components/CodePanel';
import { Button, cx, EmptyState, ErrorState, LoadingState, Panel, StatusBadge, type Tone } from '../../components/ui';

function messageOf(error: unknown) {
  return error instanceof Error ? error.message : 'Unknown inspection error';
}

function severityTone(severity: 'safe' | Severity): Tone {
  if (severity === 'safe') return 'emerald';
  if (severity === 'critical' || severity === 'high') return 'rose';
  if (severity === 'medium') return 'amber';
  return 'slate';
}

function ThreatSummary({ result }: { result: ThreatInspectResult | null }) {
  const tone = result ? severityTone(result.risk_level) : 'slate';
  const detected = result?.threats.length;
  return (
    <div aria-label="Inspection risk summary" role="status" className="grid grid-cols-2 overflow-hidden rounded-md border border-border bg-panel lg:grid-cols-5">
      <div className="relative border-b border-r border-border/70 p-3 lg:border-b-0">
        <div className="flex items-center gap-2 text-[8px] font-semibold uppercase tracking-[0.07em] text-slate-500"><Crosshair size={11} /> Risk Level</div>
        <p className={cx('mt-2 font-mono text-[20px] font-semibold uppercase', tone === 'rose' ? 'text-rose' : tone === 'emerald' ? 'text-emerald' : tone === 'amber' ? 'text-amber' : 'text-slate-300')}>{result?.risk_level ?? '—'}</p>
        <p className="mt-1 font-mono text-[8px] text-slate-600">
          {detected === undefined ? 'Awaiting inspection' : `${detected} ${detected === 1 ? 'finding' : 'findings'} detected`}
        </p>
      </div>
      <div aria-label="Cleaned in source" className="border-b border-border/70 p-3 lg:border-b-0 lg:border-r">
        <div className="flex items-center gap-2 text-[8px] font-semibold uppercase tracking-[0.07em] text-slate-500"><Layers3 size={11} /> Cleaned in source</div>
        <p className="mt-2 font-mono text-[20px] font-semibold text-emerald">{result?.cleaned_in_enhanced_count ?? '—'}</p>
      </div>
      <div aria-label="Leaked in upstream" className="border-b border-border/70 p-3 lg:border-b-0 lg:border-r">
        <div className="flex items-center gap-2 text-[8px] font-semibold uppercase tracking-[0.07em] text-slate-500"><ShieldAlert size={11} /> Leaked in Upstream v1.2.4</div>
        <p className="mt-2 font-mono text-[20px] font-semibold text-rose">{result?.leaked_in_upstream_count ?? '—'}</p>
        <p className="mt-1 font-mono text-[8px] text-slate-600">Unsanitized indirect instructions</p>
      </div>
      <div aria-label="Upstream leaks removed" className="border-r border-border/70 p-3">
        <div className="flex items-center gap-2 text-[8px] font-semibold uppercase tracking-[0.07em] text-slate-500"><ShieldCheck size={11} /> Upstream leaks removed</div>
        <p className="mt-2 font-mono text-[20px] font-semibold text-emerald">{result?.blocked_in_enhanced_count ?? '—'}</p>
      </div>
      <div className="p-3">
        <div className="flex items-center gap-2 text-[8px] font-semibold uppercase tracking-[0.07em] text-slate-500"><Clock3 size={11} /> Elapsed</div>
        <p className="mt-2 font-mono text-[20px] font-semibold text-cyan">{result ? `${result.elapsed_us} μs` : '—'}</p>
        <p className="mt-1 font-mono text-[8px] text-slate-600">Full threat surface analysis</p>
      </div>
    </div>
  );
}

function ColumnCounts({ result }: { result: TableNormalizeResult }) {
  const rowCount = Math.max(result.upstream_column_counts.length, result.normalized_column_counts.length);
  return (
    <div aria-label="Table column counts" className="border-t border-border bg-background/25 p-3">
      <div className="mb-2 flex items-center justify-between">
        <span className="micro-label">Per-row pipe alignment</span>
        <span className="font-mono text-[8px] text-slate-600">UPSTREAM <ArrowRight className="mx-1 inline" size={9} /> NORMALIZED</span>
      </div>
      <div className="grid gap-1.5 sm:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: rowCount }, (_, index) => {
          const before = result.upstream_column_counts[index];
          const after = result.normalized_column_counts[index];
          const repaired = before !== after;
          return (
            <div key={`count-${index}`} className="flex items-center gap-2 rounded border border-border/70 bg-panel px-2 py-1.5 font-mono text-[8px]">
              <span className="w-9 text-slate-600">ROW {index + 1}</span>
              <span className={repaired ? 'text-rose' : 'text-slate-300'}>{before ?? '—'} COL</span>
              <ArrowRight size={9} className="text-slate-700" />
              <span className="text-emerald">{after ?? '—'} COL</span>
              <span className={cx('ml-auto h-1.5 w-1.5 rounded-full', repaired ? 'bg-amber' : 'bg-emerald')} title={repaired ? 'Span expanded' : 'Already aligned'} />
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function ThreatInspectorLab() {
  const [presets, setPresets] = useState<Preset[]>([]);
  const [selectedPreset, setSelectedPreset] = useState('');
  const [inspectHtml, setInspectHtml] = useState('');
  const [tableHtml, setTableHtml] = useState('');
  const [inspection, setInspection] = useState<ThreatInspectResult | null>(null);
  const [tableResult, setTableResult] = useState<TableNormalizeResult | null>(null);
  const [inspecting, setInspecting] = useState(false);
  const [normalizing, setNormalizing] = useState(false);
  const [inspectionError, setInspectionError] = useState<string | null>(null);
  const [tableError, setTableError] = useState<string | null>(null);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const inspectionRequest = useRef(0);
  const tableRequest = useRef(0);

  const runInspection = useCallback(async (payload = inspectHtml) => {
    const id = ++inspectionRequest.current;
    setInspecting(true);
    setInspectionError(null);
    try {
      const next = await api.inspectThreats(payload);
      if (id === inspectionRequest.current) setInspection(next);
    } catch (error) {
      if (id === inspectionRequest.current) setInspectionError(messageOf(error));
    } finally {
      if (id === inspectionRequest.current) setInspecting(false);
    }
  }, [inspectHtml]);

  const runNormalization = useCallback(async (payload = tableHtml) => {
    const id = ++tableRequest.current;
    setNormalizing(true);
    setTableError(null);
    try {
      const next = await api.normalizeTable(payload);
      if (id === tableRequest.current) setTableResult(next);
    } catch (error) {
      if (id === tableRequest.current) setTableError(messageOf(error));
    } finally {
      if (id === tableRequest.current) setNormalizing(false);
    }
  }, [tableHtml]);

  useEffect(() => {
    let mounted = true;
    const bootstrap = async () => {
      try {
        const data = await api.presets();
        if (!mounted) return;
        setPresets(data);
        const first = data[0];
        const tablePreset = data.find((preset) => preset.html.toLowerCase().includes('<table')) ?? first;
        if (first) {
          setSelectedPreset(first.id);
          setInspectHtml(first.html);
          void runInspection(first.html);
        }
        if (tablePreset) {
          setTableHtml(tablePreset.html);
          void runNormalization(tablePreset.html);
        }
      } catch (error) {
        if (mounted) setCatalogError(messageOf(error));
      }
    };
    void bootstrap();
    return () => {
      mounted = false;
      inspectionRequest.current += 1;
      tableRequest.current += 1;
    };
    // The initial real preset defines both automatic analyses.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const selectPreset = (id: string) => {
    const preset = presets.find((candidate) => candidate.id === id);
    if (!preset) return;
    setSelectedPreset(id);
    setInspectHtml(preset.html);
    void runInspection(preset.html);
    if (preset.html.toLowerCase().includes('<table')) {
      setTableHtml(preset.html);
      void runNormalization(preset.html);
    }
  };

  return (
    <div className="mx-auto max-w-[1800px] space-y-3">
      <div className="flex flex-col gap-3 rounded-md border border-border bg-panel p-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="grid h-9 w-9 place-items-center rounded border border-rose/25 bg-rose/[0.07] text-rose"><ScanSearch size={18} aria-hidden="true" /></div>
          <div>
            <h2 className="text-[11px] font-semibold tracking-[0.035em] text-slate-200">INDIRECT PROMPT-INJECTION SURFACE MAP</h2>
            <p className="mt-1 font-mono text-[8px] text-slate-600">Locate hidden instructions before they enter the agent context window.</p>
          </div>
        </div>
        <label className="flex items-center gap-2 text-[9px] text-slate-500">
          <span className="micro-label">Scenario</span>
          <select aria-label="Inspection scenario" value={selectedPreset} onChange={(event) => selectPreset(event.target.value)} className="max-w-64 rounded border border-border bg-raised px-2 py-2 font-mono text-[9px] text-slate-300 outline-none focus:border-cyan">
            {!presets.length && <option value="">Loading scenarios…</option>}
            {presets.map((preset) => <option key={preset.id} value={preset.id}>{preset.title}</option>)}
          </select>
        </label>
      </div>

      {catalogError && <ErrorState message={catalogError} />}
      <ThreatSummary result={inspection} />

      <div className="grid min-w-0 gap-3 xl:grid-cols-[minmax(0,1.65fr)_minmax(280px,0.75fr)]">
        <div className="min-w-0 space-y-3">
          <Panel title="Untrusted HTML / Threat Analysis Input" actions={<StatusBadge tone="rose">UNTRUSTED DOM</StatusBadge>} className="flex h-[230px] flex-col" bodyClassName="flex min-h-0 flex-1 flex-col">
            <div className="min-h-0 flex-1"><HtmlEditor value={inspectHtml} onChange={setInspectHtml} ariaLabel="Threat inspection HTML" /></div>
            <div className="flex h-11 flex-none items-center justify-between border-t border-border px-3">
              <span className="font-mono text-[8px] text-slate-600">DOM PATH + INSTRUCTION OVERRIDE ANALYSIS</span>
              <Button variant="primary" disabled={inspecting || !inspectHtml.trim()} onClick={() => void runInspection()} className="py-1.5"><ScanSearch size={11} />{inspecting ? 'Inspecting…' : 'Inspect Threats'}</Button>
            </div>
          </Panel>

          <div className="grid min-w-0 gap-3 lg:grid-cols-2">
            <Panel title="Upstream Leaked Markdown" actions={<StatusBadge tone="rose">{inspection?.leaked_in_upstream_count ?? 0} LEAKS</StatusBadge>} className="h-[285px] lg:h-[310px]" bodyClassName="h-[calc(100%-33px)]">
              <CodeView code={inspection?.upstream_markdown_preview ?? ''} ariaLabel="Upstream leaked Markdown" empty="No upstream preview" compact />
            </Panel>
            <Panel title="Enhanced Protected Markdown" actions={<StatusBadge tone="emerald">DOM GUARD</StatusBadge>} className="h-[285px] lg:h-[310px]" bodyClassName="h-[calc(100%-33px)]">
              <CodeView code={inspection?.enhanced_markdown_preview ?? ''} ariaLabel="Enhanced protected Markdown" empty="No enhanced preview" compact />
            </Panel>
          </div>
        </div>

        <Panel title={`Threat Findings (${inspection?.threats.length ?? 0})`} actions={<span className="micro-label">SEVERITY / ACTION</span>} className="min-h-[400px] xl:h-[553px]" bodyClassName="code-scroll h-[calc(100%-33px)] overflow-y-auto p-2">
          {inspecting && !inspection ? <LoadingState label="SCANNING INDIRECT INJECTION VECTORS" /> : inspectionError ? (
            <ErrorState message={inspectionError} onRetry={() => void runInspection()} retryLabel="Retry inspection" />
          ) : inspection?.threats.length ? (
            <div className="space-y-2">
              {inspection.threats.map((threat, index) => (
                <article key={`threat-${threat.id}-${index}`} className="rounded border border-border/80 bg-background/35 p-3 transition-colors hover:border-slate-600">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <StatusBadge tone={severityTone(threat.severity)}>{threat.severity}</StatusBadge>
                    <span className="font-mono text-[9px] font-medium text-slate-300">{threat.category}</span>
                    <span className="ml-auto font-mono text-[7px] text-slate-700">#{String(index + 1).padStart(2, '0')}</span>
                  </div>
                  <p className="mt-2 truncate font-mono text-[8px] text-cyan/70" title={threat.dom_path}>{threat.dom_path}</p>
                  <code className="mt-2 block whitespace-pre-wrap break-words rounded border border-rose/10 bg-rose/[0.035] p-2 font-mono text-[8px] leading-4 text-slate-400">{threat.snippet}</code>
                  <div className="mt-2 flex items-center justify-between">
                    <span className="micro-label">Guard action</span>
                    <StatusBadge tone={threat.action === 'flagged' ? 'rose' : threat.action === 'stripped' ? 'emerald' : 'cyan'}>{threat.action}</StatusBadge>
                  </div>
                </article>
              ))}
            </div>
          ) : inspection ? (
            <div className="flex h-full min-h-64 flex-col items-center justify-center p-5 text-center">
              <CheckCircle2 size={28} className="text-emerald" strokeWidth={1.3} />
              <p className="mt-3 font-mono text-[10px] font-semibold text-emerald">NO INDIRECT INJECTION DETECTED</p>
              <p className="mt-2 max-w-56 text-[9px] leading-4 text-slate-600">No hidden DOM, unicode smuggling, instruction override or exfiltration URI was identified.</p>
            </div>
          ) : <EmptyState title="No inspection" detail="Run the inspector to populate detailed findings." />}
        </Panel>
      </div>

      <Panel title="2D Table Span & Pipe Alignment Tester" actions={<div className="flex items-center gap-2"><StatusBadge tone={tableResult?.upstream_aligned ? 'emerald' : 'rose'}>{tableResult?.upstream_aligned ? 'UPSTREAM 100% ALIGNED' : 'UPSTREAM MISALIGNED'}</StatusBadge><StatusBadge tone={tableResult?.normalized_aligned ? 'emerald' : 'rose'}>{tableResult?.normalized_aligned ? 'ENHANCED 100% ALIGNED' : 'ENHANCED MISALIGNED'}</StatusBadge></div>} className="min-h-[380px]">
        {tableError ? <ErrorState message={tableError} onRetry={() => void runNormalization()} retryLabel="Retry normalization" /> : normalizing && !tableResult ? <LoadingState label="RECTANGULARIZING TABLE GRID" /> : tableResult ? (
          <div>
            <div className="grid min-w-0 lg:grid-cols-[minmax(280px,0.72fr)_minmax(0,1.28fr)]">
              <div className="flex h-[270px] flex-col border-b border-border lg:border-b-0 lg:border-r">
                <div className="min-h-0 flex-1"><HtmlEditor value={tableHtml} onChange={setTableHtml} ariaLabel="Table normalization HTML" /></div>
                <div className="flex h-11 flex-none items-center justify-between border-t border-border px-3">
                  <span className="flex items-center gap-1.5 font-mono text-[8px] text-amber"><Table2 size={10} />{tableResult.cells_expanded} cells expanded</span>
                  <Button variant="primary" disabled={normalizing || !tableHtml.trim()} onClick={() => void runNormalization()} className="py-1.5"><Layers3 size={11} />{normalizing ? 'Normalizing…' : 'Normalize Table'}</Button>
                </div>
              </div>
              <div className="grid min-w-0 grid-cols-1 md:grid-cols-2">
                <div className="h-[270px] border-b border-border md:border-b-0 md:border-r">
                  <div className="flex h-8 items-center gap-2 border-b border-border px-3 font-mono text-[8px] text-rose"><Braces size={10} /> UPSTREAM TABLE</div>
                  <div className="h-[calc(100%-32px)]"><CodeView code={tableResult.upstream_table_markdown} ariaLabel="Upstream table Markdown" compact /></div>
                </div>
                <div className="h-[270px]">
                  <div className="flex h-8 items-center gap-2 border-b border-border px-3 font-mono text-[8px] text-emerald"><Braces size={10} /> NORMALIZED TABLE</div>
                  <div className="h-[calc(100%-32px)]"><CodeView code={tableResult.normalized_table_markdown} ariaLabel="Normalized table Markdown" compact /></div>
                </div>
              </div>
            </div>
            <ColumnCounts result={tableResult} />
          </div>
        ) : <EmptyState title="No table analysis" detail="Provide an HTML table with colspan or rowspan cells and run normalization." />}
      </Panel>
    </div>
  );
}
