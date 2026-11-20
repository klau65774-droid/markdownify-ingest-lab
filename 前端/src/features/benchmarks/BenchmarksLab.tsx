import { useEffect, useRef, useState } from 'react';
import { Activity, BarChart3, CheckCircle2, Clock3, Database, Gauge, Play, ShieldCheck, XCircle } from 'lucide-react';
import { api } from '../../api/client';
import { AUDIT_CHECK_NAMES, BENCHMARK_CATEGORIES, POLICIES } from '../../api/contract';
import type { AuditResult, BenchmarkMetrics, BenchmarkResult, Policy } from '../../api/types';
import { Button, cx, EmptyState, ErrorState, LoadingState, Panel, StatusBadge } from '../../components/ui';

type MetricKey = 'injection_block_rate' | 'content_f1' | 'token_reduction_rate' | 'table_alignment_rate' | 'p95_us' | 'p99_us';

const metricDefinitions: Array<{ key: MetricKey; label: string; hint: string; latency?: boolean }> = [
  { key: 'injection_block_rate', label: 'Injection Block Rate', hint: 'Higher is better' },
  { key: 'content_f1', label: 'Content Token F1', hint: 'Higher is better' },
  { key: 'token_reduction_rate', label: 'Token Noise Reduction', hint: 'Higher reduction is better' },
  { key: 'table_alignment_rate', label: 'Table Alignment Rate', hint: 'Higher is better' },
  { key: 'p95_us', label: 'P95 Latency', hint: 'Lower is better', latency: true },
  { key: 'p99_us', label: 'P99 Latency', hint: 'Lower is better', latency: true },
];

const policyStyles: Record<Policy, { text: string; bar: string; border: string }> = {
  raw_upstream: { text: 'text-rose', bar: 'bg-rose', border: 'border-rose/25' },
  clean_rag: { text: 'text-amber', bar: 'bg-amber', border: 'border-amber/25' },
  strict_guard: { text: 'text-cyan', bar: 'bg-cyan', border: 'border-cyan/25' },
};

function messageOf(error: unknown) {
  return error instanceof Error ? error.message : 'Unknown benchmark engine error';
}

function metricSampleCount(key: MetricKey, metrics?: BenchmarkMetrics) {
  if (key === 'injection_block_rate') return metrics?.injection_count;
  if (key === 'table_alignment_rate') return metrics?.table_case_count;
  return undefined;
}

function formatMetric(key: MetricKey, metrics?: BenchmarkMetrics) {
  const count = metricSampleCount(key, metrics);
  if (count === 0) return 'N/A (0 cases)';
  const value = metrics?.[key];
  if (value == null) return 'N/A';
  if (key === 'p95_us' || key === 'p99_us') return `${Math.round(value)} μs`;
  const percent = value * 100;
  if (key === 'token_reduction_rate') return `${percent >= 0 ? '-' : '+'}${Math.abs(percent).toFixed(1)}%`;
  const formatted = `${percent.toFixed(1)}%`;
  return count === undefined ? formatted : `${formatted} (${count} cases)`;
}

function MetricBars({ result }: { result: BenchmarkResult }) {
  return (
    <div className="grid gap-2 md:grid-cols-2 2xl:grid-cols-3">
      {metricDefinitions.map((definition) => {
        const values = POLICIES.map((policy) => {
          const metrics = result.modes[policy];
          const value = metricSampleCount(definition.key, metrics) === 0 ? 0 : metrics?.[definition.key] ?? 0;
          return { policy, metrics, value };
        });
        const max = Math.max(...values.map(({ value }) => Math.abs(value)), 1);
        return (
          <article key={definition.key} className="rounded border border-border/80 bg-background/30 p-3">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-[10px] font-medium text-slate-300">{definition.label}</h3>
              <span className="micro-label">{definition.hint}</span>
            </div>
            <div className="mt-3 space-y-2.5">
              {values.map(({ policy, metrics, value }) => {
                const width = Math.max(0, Math.min(100, Math.abs(value) / max * 100));
                return (
                  <div key={policy} className="grid grid-cols-[86px_minmax(0,1fr)_58px] items-center gap-2">
                    <span className="truncate font-mono text-[8px] text-slate-500">{policy}</span>
                    <div className="h-1.5 overflow-hidden rounded-full bg-slate-800/70">
                      <div className={cx('h-full rounded-full opacity-80 transition-[width] duration-500', policyStyles[policy].bar)} style={{ width: `${width}%` }} />
                    </div>
                    <span className={cx('text-right font-mono text-[9px]', policyStyles[policy].text)}>{formatMetric(definition.key, metrics)}</span>
                  </div>
                );
              })}
            </div>
          </article>
        );
      })}
    </div>
  );
}

function MetricsTable({ result }: { result: BenchmarkResult }) {
  return (
    <div className="code-scroll mt-3 overflow-x-auto rounded border border-border/80">
      <table className="w-full min-w-[660px] border-collapse text-left">
        <thead className="bg-raised/70">
          <tr className="border-b border-border font-mono text-[8px] uppercase text-slate-500">
            <th className="px-3 py-2 font-medium">Metric / policy</th>
            {POLICIES.map((policy) => <th key={policy} className={cx('px-3 py-2 text-right font-medium', policyStyles[policy].text)}>{policy}</th>)}
          </tr>
        </thead>
        <tbody>
          {metricDefinitions.map((definition) => (
            <tr key={definition.key} className="border-b border-border/50 last:border-0 hover:bg-white/[0.015]">
              <th className="px-3 py-2.5 text-[9px] font-medium text-slate-400">{definition.label}</th>
              {POLICIES.map((policy) => {
                return <td key={policy} className="px-3 py-2.5 text-right font-mono text-[9px] text-slate-300">{formatMetric(definition.key, result.modes[policy])}</td>;
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CategoryMatrix({ result }: { result: BenchmarkResult }) {
  return (
    <div aria-label="Eight-category benchmark matrix" className="code-scroll overflow-x-auto">
      <table className="w-full min-w-[900px] border-collapse text-left">
        <thead className="bg-raised/65">
          <tr className="border-b border-border text-[8px] uppercase tracking-[0.05em] text-slate-500">
            <th className="w-[230px] px-3 py-2.5 font-medium">Fault category</th>
            {POLICIES.map((policy) => <th key={policy} className={cx('px-3 py-2.5 font-mono font-medium', policyStyles[policy].text)}>{policy}</th>)}
          </tr>
        </thead>
        <tbody>
          {BENCHMARK_CATEGORIES.map((category, categoryIndex) => (
            <tr key={category} className="border-b border-border/50 last:border-0 hover:bg-white/[0.015]">
              <th className="px-3 py-3 font-mono text-[9px] font-normal text-slate-400">
                <span className="mr-2 text-slate-700">{String(categoryIndex + 1).padStart(2, '0')}</span>{category}
              </th>
              {POLICIES.map((policy) => {
                const metrics: BenchmarkMetrics | undefined = result.by_category[category]?.[policy];
                return (
                  <td key={policy} className="px-3 py-2.5" title={metrics ? `P95 ${metrics.p95_us} μs · P99 ${metrics.p99_us} μs · ${metrics.case_count} cases` : 'No data'}>
                    {metrics ? (
                      <div className="grid grid-cols-2 gap-x-3 gap-y-1 font-mono text-[8px]">
                        <span className="text-slate-600">BLOCK <span className={policyStyles[policy].text}>{formatMetric('injection_block_rate', metrics)}</span></span>
                        <span className="text-slate-600">F1 <span className="text-slate-300">{formatMetric('content_f1', metrics)}</span></span>
                        <span className="text-slate-600">ALIGN <span className="text-slate-300">{formatMetric('table_alignment_rate', metrics)}</span></span>
                        <span className="text-slate-600">NOISE <span className="text-emerald">{formatMetric('token_reduction_rate', metrics)}</span></span>
                      </div>
                    ) : <span className="font-mono text-[9px] text-slate-700">N/A</span>}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AuditCards({ result }: { result: AuditResult | null }) {
  return (
    <div aria-label="DoS and secret redaction audit" className="grid gap-2 p-3 sm:grid-cols-2 xl:grid-cols-4">
      {AUDIT_CHECK_NAMES.map((name) => {
        const check = result?.checks.find((candidate) => candidate.name === name);
        const passed = check?.status === 'PASS';
        return (
          <article key={name} className={cx('rounded border bg-background/30 p-3', check ? passed ? 'border-emerald/20' : 'border-rose/30' : 'border-dashed border-border')}>
            <div className="flex items-start justify-between gap-2">
              <div className="flex min-w-0 items-center gap-2">
                {check ? passed ? <CheckCircle2 size={14} className="flex-none text-emerald" /> : <XCircle size={14} className="flex-none text-rose" /> : <ShieldCheck size={14} className="flex-none text-slate-700" />}
                <h3 className="break-all font-mono text-[9px] font-medium leading-4 text-slate-300">{name}</h3>
              </div>
              <StatusBadge tone={check ? passed ? 'emerald' : 'rose' : 'slate'}>{check?.status ?? 'NO DATA'}</StatusBadge>
            </div>
            <div className="mt-3 flex items-center gap-1.5 font-mono text-[9px] text-cyan"><Clock3 size={10} />{check ? `${check.elapsed_us} μs` : '—'}</div>
            <dl className="mt-3 space-y-1.5 border-t border-border/60 pt-2">
              {check ? Object.entries(check.details).map(([key, value]) => (
                <div key={key} className="flex items-start justify-between gap-2 font-mono text-[8px]">
                  <dt className="break-all text-slate-600">{key}</dt><dd className="break-all text-right text-slate-400">{String(value)}</dd>
                </div>
              )) : <p className="font-mono text-[8px] text-slate-700">Awaiting observed metrics</p>}
            </dl>
          </article>
        );
      })}
    </div>
  );
}

export function BenchmarksLab() {
  const [benchmarks, setBenchmarks] = useState<BenchmarkResult | null>(null);
  const [audit, setAudit] = useState<AuditResult | null>(null);
  const [benchmarking, setBenchmarking] = useState(false);
  const [auditing, setAuditing] = useState(false);
  const [benchmarkError, setBenchmarkError] = useState<string | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);
  const benchmarkRequest = useRef(0);
  const auditRequest = useRef(0);

  useEffect(() => () => {
    benchmarkRequest.current += 1;
    auditRequest.current += 1;
  }, []);

  const runBenchmarks = async () => {
    const id = ++benchmarkRequest.current;
    setBenchmarking(true);
    setBenchmarkError(null);
    try {
      const next = await api.runBenchmarks();
      if (id === benchmarkRequest.current) setBenchmarks(next);
    } catch (error) {
      if (id === benchmarkRequest.current) setBenchmarkError(messageOf(error));
    } finally {
      if (id === benchmarkRequest.current) setBenchmarking(false);
    }
  };

  const runAudit = async () => {
    const id = ++auditRequest.current;
    setAuditing(true);
    setAuditError(null);
    try {
      const next = await api.runDosAudit();
      if (id === auditRequest.current) setAudit(next);
    } catch (error) {
      if (id === auditRequest.current) setAuditError(messageOf(error));
    } finally {
      if (id === auditRequest.current) setAuditing(false);
    }
  };

  return (
    <div className="mx-auto max-w-[1800px] space-y-3">
      <div className="flex flex-col gap-3 rounded-md border border-border bg-panel p-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-3">
          <div className="grid h-9 w-9 place-items-center rounded border border-cyan/25 bg-cyan/[0.07] text-cyan"><Gauge size={18} /></div>
          <div>
            <h2 className="text-[11px] font-semibold tracking-[0.035em] text-slate-200">WEB EXTRACTION & BIPIA BENCHMARK CONTROL</h2>
            <p className="mt-1 font-mono text-[8px] text-slate-600">40-case multi-fault corpus · three policies · deterministic resource-budget audit.</p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" disabled={benchmarking} onClick={() => void runBenchmarks()}><BarChart3 size={12} />{benchmarking ? 'Running 40 Cases…' : 'Run 40-Case Benchmark'}</Button>
          <Button variant="primary" disabled={auditing} onClick={() => void runAudit()}><Play size={11} fill="currentColor" />{auditing ? 'Running Security Audit…' : 'Run DoS & Secret Audit'}</Button>
        </div>
      </div>

      {benchmarkError && <ErrorState message={benchmarkError} onRetry={() => void runBenchmarks()} retryLabel="Retry benchmarks" />}
      {benchmarking && !benchmarks ? <Panel><LoadingState label="EXECUTING 40 MULTI-FAULT & BIPIA CASES" /></Panel> : benchmarks ? (
        <section aria-label="Benchmark comparison" className="space-y-3">
          <Panel>
            <div className="flex flex-col gap-2 border-b border-border p-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2">
                <Database size={13} className="text-cyan" />
                <h2 className="section-caption">Policy Comparison / Aggregate Metrics</h2>
              </div>
              <div className="flex items-center gap-2 font-mono text-[8px]"><StatusBadge tone="cyan">{benchmarks.case_count} CASES</StatusBadge><StatusBadge tone="slate">8 CATEGORIES</StatusBadge><span className="text-slate-600">{benchmarks.sample_results.length} SAMPLE RECORDS</span></div>
            </div>
            <div className="p-3"><MetricBars result={benchmarks} /><MetricsTable result={benchmarks} /></div>
          </Panel>
          <Panel title="8-Category Breakdown Matrix" actions={<span className="micro-label">BLOCK / F1 / ALIGN / NOISE</span>}><CategoryMatrix result={benchmarks} /></Panel>
        </section>
      ) : (
        <Panel className="min-h-40"><EmptyState title="BENCHMARKS NOT RUN" detail="Execute the 40-case corpus to compare raw upstream, clean RAG and strict guard across all six quality and latency metrics." /></Panel>
      )}

      <Panel
        title="DoS Budget & Secret Redaction Audit"
        actions={audit ? <StatusBadge tone={audit.status === 'PASS' ? 'emerald' : 'rose'} dot>{audit.status} · {audit.checks.length} CHECKS</StatusBadge> : <StatusBadge tone="slate">AUDIT IDLE</StatusBadge>}
      >
        {auditError && <ErrorState message={auditError} onRetry={() => void runAudit()} retryLabel="Retry audit" />}
        {auditing && !audit ? <LoadingState label="PROBING DEPTH · SIZE · QUADRATIC · CREDENTIAL BUDGETS" /> : audit ? <AuditCards result={audit} /> : (
          <div>
            <div className="flex items-center gap-2 border-b border-border/60 bg-amber/[0.025] px-3 py-2 font-mono text-[8px] text-slate-600"><Activity size={10} className="text-amber" />AUDIT NOT RUN · No synthetic security results are displayed.</div>
            <AuditCards result={null} />
          </div>
        )}
      </Panel>
    </div>
  );
}
