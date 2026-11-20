import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Check,
  ChevronRight,
  Clock3,
  Play,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { api } from '../../api/client';
import type { IngestResultModel, Policy, Preset } from '../../api/types';
import { CodeView, HtmlEditor } from '../../components/CodePanel';
import {
  Button,
  cx,
  EmptyState,
  ErrorState,
  LoadingState,
  MetricRow,
  Panel,
  StatusBadge,
  Toggle,
  type Tone,
} from '../../components/ui';
import { toAuditOperations, type AuditOperation } from './audit';

const policyOptions: Array<{ id: Policy; lines: [string, string]; label: string }> = [
  { id: 'raw_upstream', lines: ['Raw', 'Upstream'], label: 'Raw Upstream' },
  { id: 'clean_rag', lines: ['Clean', 'RAG'], label: 'Clean RAG' },
  { id: 'strict_guard', lines: ['Strict', 'Guard'], label: 'Strict Guard' },
];

const actionTone: Record<string, Tone> = {
  STRIP_HIDDEN_STYLE: 'rose', STRIP_HIDDEN_ATTR: 'rose', STRIP_ZERO_WIDTH: 'rose',
  STRIP_SUSPICIOUS_ATTRIBUTE: 'rose', STRIP_INSTRUCTION: 'rose', STRIP_DANGEROUS_URI: 'rose',
  PRUNE_BOILERPLATE: 'emerald', NORMALIZE_TABLE: 'amber', CLEAN_TRACKING_URL: 'cyan',
  REDACT_SECRET: 'rose', STRIP_TRACKING_PIXEL: 'amber',
};

function riskTone(risk: AuditOperation['risk']): Tone {
  if (risk === 'CRITICAL' || risk === 'HIGH') return 'rose';
  if (risk === 'MEDIUM') return 'amber';
  return 'slate';
}

function formatReduction(rate: number | null): string {
  if (rate === null) return 'N/A';
  const percent = Math.abs(rate) <= 1 ? rate * 100 : rate;
  return `${percent >= 0 ? '-' : '+'}${Math.abs(percent).toFixed(1)}%`;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : 'Unknown ingest engine error';
}

function AuditTrace({ operations }: { operations: AuditOperation[] }) {
  if (!operations.length) {
    return <EmptyState title="No mutations required" detail="The guard emitted no DOM, table, link or post-processing operations for this payload." />;
  }
  return (
    <div className="code-scroll min-h-0 flex-1 overflow-auto">
      <table className="w-full min-w-[790px] border-collapse text-left">
        <thead className="sticky top-0 z-10 bg-raised/95 backdrop-blur">
          <tr className="border-b border-border text-[8px] uppercase tracking-[0.06em] text-slate-500">
            <th className="w-9 px-3 py-2 font-medium">#</th>
            <th className="w-16 px-2 py-2 font-medium">Stage</th>
            <th className="w-[190px] px-2 py-2 font-medium">Action badge</th>
            <th className="w-[190px] px-2 py-2 font-medium">DOM selector / path</th>
            <th className="px-2 py-2 font-medium">Removed / transformed snippet</th>
            <th className="w-20 px-3 py-2 text-right font-medium">Risk</th>
          </tr>
        </thead>
        <tbody>
          {operations.map((op, index) => (
            <tr key={`op-${index}-${op.stage}-${op.op}-${op.dom_path}`} className="border-b border-border/50 text-[9px] transition-colors last:border-0 hover:bg-white/[0.018]">
              <td className="px-3 py-2.5 font-mono text-slate-600">{index + 1}</td>
              <td className="px-2 py-2.5 font-mono text-slate-400">{op.stage}</td>
              <td className="px-2 py-2.5"><StatusBadge tone={actionTone[op.kind]}>{op.actionLabel}</StatusBadge></td>
              <td className="max-w-0 truncate px-2 py-2.5 font-mono text-slate-400" title={op.dom_path}>{op.dom_path}</td>
              <td className="max-w-0 truncate px-2 py-2.5 font-mono text-slate-500" title={op.detail}>
                {op.detail}{op.count && op.count > 1 ? ` ×${op.count}` : ''}
              </td>
              <td className="px-3 py-2.5 text-right"><span className={cx('font-mono text-[8px] font-semibold', riskTone(op.risk) === 'amber' ? 'text-amber' : riskTone(op.risk) === 'rose' ? 'text-rose' : 'text-slate-500')}>{op.risk}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function BaselineCard({ result, canRequest, onRequest }: {
  result: IngestResultModel | null;
  canRequest: boolean;
  onRequest: () => void;
}) {
  const baseline = result?.baseline;
  if (!baseline) {
    return (
      <div className="rounded border border-dashed border-border bg-background/30 p-3 text-center">
        <span className="font-mono text-[9px] text-slate-500">BASELINE NOT REQUESTED</span>
        <Button className="mt-2" disabled={!canRequest} onClick={onRequest}>
          View Unredacted Upstream Markdown
        </Button>
      </div>
    );
  }
  const hasLeaks = baseline.leaked_threat_count > 0;
  const hasIssue = hasLeaks || !baseline.table_alignment_valid;
  return (
    <div className={cx('rounded border p-3', hasIssue ? 'border-rose/25 bg-rose/[0.055]' : 'border-emerald/25 bg-emerald/[0.05]')}>
      <div className="flex items-start gap-2">
        <ShieldAlert size={15} className={hasIssue ? 'text-rose' : 'text-emerald'} aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <p className="text-[9px] text-slate-400">Unredacted upstream <span className="float-right font-mono text-[8px] text-slate-600">v{baseline.version}</span></p>
          <p className={cx('mt-1 text-[16px] font-semibold tracking-[-0.02em]', hasIssue ? 'text-rose' : 'text-emerald')}>
            {hasLeaks ? 'UPSTREAM LEAKS DETECTED' : hasIssue ? 'TABLE MISALIGNED' : 'NO MATCHED LEAKS'}
          </p>
        </div>
      </div>
      <div className="mt-2 flex flex-wrap gap-x-2 gap-y-1 font-mono text-[8px] text-slate-500">
        <span className={baseline.leaked_threat_count ? 'text-rose/80' : ''}>{baseline.leaked_threat_count} leaked threats</span><span>·</span>
        <span>{baseline.token_count} tokens</span><span>·</span><span>{baseline.elapsed_us} μs</span>
      </div>
      <pre className="mt-2 max-h-14 overflow-hidden whitespace-pre-wrap break-words border-t border-white/[0.035] pt-2 font-mono text-[8px] leading-3 text-slate-600">{baseline.markdown || 'Empty upstream output'}</pre>
    </div>
  );
}

function EnhancedCard({ result, protected: isProtected }: { result: IngestResultModel | null; protected: boolean }) {
  if (!result) {
    return <div className="rounded border border-dashed border-border p-3 text-center font-mono text-[9px] text-slate-600">AWAITING ENHANCED RUN</div>;
  }
  return (
    <div className={cx('rounded border p-3', isProtected ? 'border-emerald/30 bg-emerald/[0.06] shadow-[inset_0_0_22px_rgba(16,185,129,0.025)]' : 'border-rose/30 bg-rose/[0.06]')}>
      <div className="flex items-start gap-2">
        <ShieldCheck size={15} className={isProtected ? 'text-emerald' : 'text-rose'} aria-hidden="true" />
        <div>
          <p className="text-[9px] text-slate-400">Enhanced Guard:</p>
          <p className={cx('mt-1 text-[16px] font-semibold tracking-[-0.02em]', isProtected ? 'text-emerald' : 'text-rose')}>{isProtected ? 'CHECKS PASSED' : 'REVIEW OUTPUT'}</p>
        </div>
      </div>
      <div className="mt-2 font-mono text-[8px] leading-4 text-slate-500">
        <p>{result.threats.filter((threat) => threat.action === 'flagged').length} flagged findings · {result.token_count} tokens · {formatReduction(result.token_reduction_rate)} tokens</p>
        <p className="text-slate-600">Guard latency {(result.elapsed_us / 1000).toFixed(2)} ms</p>
      </div>
    </div>
  );
}

export function IngestLab() {
  const [presets, setPresets] = useState<Preset[]>([]);
  const [selectedPreset, setSelectedPreset] = useState<string | null>(null);
  const [html, setHtml] = useState('');
  const [policy, setPolicy] = useState<Policy>('strict_guard');
  const [stripHidden, setStripHidden] = useState(true);
  const [pruneBoilerplate, setPruneBoilerplate] = useState(true);
  const [normalizeTables, setNormalizeTables] = useState(true);
  const [cleanAndRedact, setCleanAndRedact] = useState(true);
  const [result, setResult] = useState<IngestResultModel | null>(null);
  const [running, setRunning] = useState(false);
  const [loadingPresets, setLoadingPresets] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [presetError, setPresetError] = useState<string | null>(null);
  const requestId = useRef(0);

  const runIngest = useCallback(async (payload = html, compareBaseline = false) => {
    const id = ++requestId.current;
    setRunning(true);
    setResult(null);
    setError(null);
    try {
      const nextResult = await api.ingest({
        html: payload,
        policy,
        strip_hidden: stripHidden,
        prune_boilerplate: pruneBoilerplate,
        normalize_tables: normalizeTables,
        clean_urls: cleanAndRedact,
        redact_secrets: cleanAndRedact,
        infer_code_language: true,
        heading_style: 'atx',
        compare_baseline: compareBaseline,
      });
      if (id === requestId.current) setResult(nextResult);
    } catch (requestError) {
      if (id === requestId.current) setError(messageOf(requestError));
    } finally {
      if (id === requestId.current) setRunning(false);
    }
  }, [html, policy, stripHidden, pruneBoilerplate, normalizeTables, cleanAndRedact]);

  const loadPresets = useCallback(async () => {
    setLoadingPresets(true);
    setPresetError(null);
    try {
      const data = await api.presets();
      setPresets(data);
      const first = data[0];
      if (first) {
        setSelectedPreset(first.id);
        setHtml(first.html);
        await runIngest(first.html);
      }
    } catch (requestError) {
      setPresetError(messageOf(requestError));
    } finally {
      setLoadingPresets(false);
    }
  }, [runIngest]);

  useEffect(() => {
    let mounted = true;
    const bootstrap = async () => {
      setLoadingPresets(true);
      try {
        const data = await api.presets();
        if (!mounted) return;
        setPresets(data);
        setPresetError(null);
        const first = data[0];
        if (first) {
          setSelectedPreset(first.id);
          setHtml(first.html);
          await runIngest(first.html);
        }
      } catch (requestError) {
        if (mounted) setPresetError(messageOf(requestError));
      } finally {
        if (mounted) setLoadingPresets(false);
      }
    };
    void bootstrap();
    return () => {
      mounted = false;
      requestId.current += 1;
    };
    // Initial policy and options define the first automatic run.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const selectPreset = (preset: Preset) => {
    setSelectedPreset(preset.id);
    setHtml(preset.html);
    void runIngest(preset.html);
  };

  const editHtml = (value: string) => {
    requestId.current += 1;
    setSelectedPreset(null);
    setHtml(value);
    setResult(null);
    setError(null);
    setRunning(false);
  };

  const operations = useMemo(() => toAuditOperations(result?.operations ?? [], result?.threats ?? []), [result]);
  const isRawResult = result?.policy === 'raw_upstream';
  const flaggedCount = result?.threats.filter((threat) => threat.action === 'flagged').length ?? 0;
  const guardPassed = !isRawResult && Boolean(result?.markdown.trim()) && Boolean(result?.table_alignment_valid) && flaggedCount === 0;
  const hiddenThreats = result?.threats.filter((threat) => ['hidden_dom', 'zero_width'].includes(threat.category) && threat.action !== 'flagged').length ?? 0;

  return (
    <div className="ingest-layout">
      <aside className="flex min-h-0 flex-col gap-2">
        <Panel title="Ingest Scenario Presets" className="flex-none" bodyClassName="p-1.5">
          {loadingPresets && !presets.length ? <LoadingState label="LOADING SCENARIOS" /> : presetError && !presets.length ? (
            <ErrorState message={presetError} onRetry={() => void loadPresets()} />
          ) : (
            <div className="space-y-1">
              {presets.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  title={preset.description}
                  aria-pressed={selectedPreset === preset.id}
                  onClick={() => selectPreset(preset)}
                  className={cx('group flex min-h-[31px] w-full items-center justify-between gap-1 rounded border px-2.5 py-1.5 text-left text-[9px] leading-3 transition-all', selectedPreset === preset.id ? 'border-cyan/45 bg-cyan/[0.13] text-cyan shadow-[inset_0_0_15px_rgba(6,182,212,0.04)]' : 'border-border/90 bg-raised/30 text-slate-400 hover:border-slate-600 hover:text-slate-200')}
                >
                  <span>{preset.title}</span>
                  <ChevronRight size={10} className={selectedPreset === preset.id ? 'text-cyan' : 'text-transparent group-hover:text-slate-600'} aria-hidden="true" />
                </button>
              ))}
              {!presets.length && <EmptyState title="No presets" detail="The engine returned an empty scenario catalog." />}
            </div>
          )}
        </Panel>

        <Panel title="Sanitization Policy" className="flex-none" bodyClassName="px-3 pb-2 pt-2.5">
          <div className="grid grid-cols-3 overflow-hidden rounded border border-border bg-background/45 p-0.5" aria-label="Sanitization policy">
            {policyOptions.map((option) => (
              <button
                key={option.id}
                type="button"
                aria-label={option.label}
                aria-pressed={policy === option.id}
                onClick={() => setPolicy(option.id)}
                className={cx('rounded-sm px-1 py-1.5 text-[9px] leading-[13px] transition-all', policy === option.id ? 'bg-cyan/[0.22] text-cyan shadow-[inset_0_0_0_1px_rgba(6,182,212,0.35)]' : 'text-slate-500 hover:bg-white/[0.025] hover:text-slate-300')}
              >
                <span className="block">{option.lines[0]}</span><span className="block">{option.lines[1]}</span>
              </button>
            ))}
          </div>
          <div className="mt-1.5">
            <Toggle label="Strip Hidden DOM / CSS Injection" checked={stripHidden} onChange={setStripHidden} />
            <Toggle label="Prune Nav/Footer Boilerplate" checked={pruneBoilerplate} onChange={setPruneBoilerplate} />
            <Toggle label="Normalize Span Tables" checked={normalizeTables} onChange={setNormalizeTables} />
            <Toggle label="Redact Secrets & Tracking URLs" checked={cleanAndRedact} onChange={setCleanAndRedact} />
          </div>
        </Panel>

        <div className="mt-auto flex-none rounded-md border border-border bg-panel p-3 text-center">
          <p className="text-[9px] font-semibold tracking-[0.04em] text-slate-300">TOKEN NOISE REDUCTION:</p>
          <p className={cx('mt-1 font-mono text-[29px] font-semibold leading-10 tracking-[-0.06em]', result ? 'text-emerald' : 'text-slate-600')}>{result ? formatReduction(result.token_reduction_rate) : '—'}</p>
          <div aria-label="Ingestion findings" className="mt-1 rounded border border-border/50 bg-background/30 px-2 py-1">
            <MetricRow label="Findings detected" value={result?.threats.length ?? '—'} tone="slate" />
            <MetricRow label="Cleaned in source" value={result?.threats_cleaned ?? '—'} tone="emerald" />
            <MetricRow label="Upstream leaks removed" value={result?.threats_blocked ?? '—'} tone="emerald" />
          </div>
        </div>
      </aside>

      <div className="grid min-h-0 grid-cols-1 gap-2 lg:grid-cols-2">
        <Panel title="Raw Untrusted HTML Payload" actions={<StatusBadge tone="rose">UNTRUSTED</StatusBadge>} className="flex min-h-[330px] flex-col" bodyClassName="flex min-h-0 flex-1 flex-col">
          <div className="min-h-0 flex-1"><HtmlEditor value={html} onChange={editHtml} /></div>
          <div className="flex h-12 flex-none items-center justify-between gap-2 border-t border-border bg-[#0c131d] px-2.5">
            <span className="font-mono text-[8px] text-slate-600">{new TextEncoder().encode(html).length} BYTES · UTF-8</span>
            <Button variant="primary" disabled={running || !html.trim()} onClick={() => void runIngest()} className="px-3 py-1.5">
              <Play size={11} fill="currentColor" aria-hidden="true" />{running ? 'Running Guard…' : 'Run Ingest & Guard'}
            </Button>
          </div>
        </Panel>

        <Panel
          title={isRawResult ? 'Raw Upstream Markdown' : 'Sanitized Agent Markdown'}
          actions={result ? (
            <StatusBadge tone={guardPassed ? 'emerald' : 'rose'} dot>
              {isRawResult ? 'RAW UPSTREAM' : guardPassed ? 'GUARD CHECKS PASSED' : !result.table_alignment_valid ? 'TABLE MISALIGNED' : 'REVIEW OUTPUT'}
            </StatusBadge>
          ) : <StatusBadge tone={running ? 'cyan' : 'slate'}>{running ? 'PROCESSING' : 'NO OUTPUT'}</StatusBadge>}
          className="flex min-h-[330px] flex-col"
          bodyClassName="min-h-0 flex-1"
        >
          {running && !result ? <LoadingState label="PARSING DOM · APPLYING GUARD" /> : error ? (
            <ErrorState message={error} onRetry={() => void runIngest()} />
          ) : result ? <CodeView code={result.markdown} ariaLabel={isRawResult ? 'Raw upstream Markdown' : 'Sanitized agent Markdown'} /> : (
            <EmptyState title="Awaiting payload" detail="Select a scenario or paste untrusted HTML, then run the ingestion guard." />
          )}
        </Panel>
      </div>

      <Panel
        title={`DOM SANITIZATION & PROMPT-INJECTION AUDIT TRACE (${operations.length} OPS)`}
        actions={<span className="flex items-center gap-1.5 font-mono text-[8px] text-slate-600"><span className={cx('h-1 w-1 rounded-full', running ? 'animate-pulse bg-cyan' : 'bg-emerald')} />{running ? 'TRACING' : 'LIVE TRACE'}</span>}
        className="flex min-h-[260px] flex-col"
        bodyClassName="flex min-h-0 flex-1 flex-col"
      >
        <AuditTrace operations={operations} />
      </Panel>

      <aside className="code-scroll flex min-h-0 flex-col gap-2 overflow-y-auto">
        <Panel title="Upstream Baseline vs Enhanced" bodyClassName="space-y-2 p-2">
          <BaselineCard result={result} canRequest={!running && Boolean(html.trim())} onRequest={() => void runIngest(html, true)} />
          <EnhancedCard result={isRawResult ? null : result} protected={guardPassed} />
        </Panel>
        <Panel title="Threat & Structure Telemetry" className="flex-1" bodyClassName="flex h-full flex-col px-3 pb-2 pt-1">
          <MetricRow label={<>Hidden CSS / Zero-<br />Width Findings</>} value={result ? `${hiddenThreats} cleaned` : '—'} tone={hiddenThreats ? 'rose' : 'emerald'} />
          <MetricRow label="Table Cell Alignment" value={result ? result.table_alignment_valid ? '100% valid' : 'Misaligned' : '—'} tone={result?.table_alignment_valid ? 'emerald' : result ? 'rose' : 'slate'} />
          <MetricRow label="Secrets Redacted" value={result?.secrets_redacted ?? '—'} tone={result?.secrets_redacted ? 'amber' : 'slate'} />
          <MetricRow label={<span className="flex items-center gap-1.5"><Clock3 size={10} /> Guard Latency</span>} value={result ? `${result.elapsed_us} μs` : '—'} tone="cyan" />
          <div className="mt-auto pt-3">
            <div className="mb-2 flex items-center justify-between font-mono text-[7px] uppercase tracking-[0.07em] text-slate-700"><span>0</span><span>Processing signal / μs</span><span>{result?.elapsed_us ?? 0}</span></div>
            <div className="latency-bars flex h-16 items-end gap-[2px] border-b border-border/70 bg-gradient-to-t from-cyan/[0.025] to-transparent px-1">
              {Array.from({ length: 32 }, (_, index) => (
                <span key={`bar-${index}`} className={cx('flex-1 rounded-t-[1px]', result ? 'bg-cyan/65' : 'bg-slate-800')} style={{ height: `${result ? 22 + ((index * 29) % 72) : 12}%` }} />
              ))}
            </div>
            <div className="mt-2 flex items-center justify-center gap-1.5 font-mono text-[8px] text-slate-600">
              {result?.table_alignment_valid && guardPassed ? <Check size={9} className="text-emerald" /> : <AlertTriangle size={9} className="text-amber" />}
              CONFIDENCE {result ? `${Math.round(result.confidence_score * 100)}%` : '—'}
            </div>
          </div>
        </Panel>
      </aside>
    </div>
  );
}
