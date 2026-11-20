import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import { BENCHMARK_CATEGORIES, POLICIES } from '../../api/contract';
import { makeAuditResult, makeBenchmarkResult } from '../../test/fixtures';
import { BenchmarksLab } from './BenchmarksLab';

vi.mock('../../api/client', () => ({
  api: { runBenchmarks: vi.fn(), runDosAudit: vi.fn() },
}));

const benchmarksMock = vi.mocked(api.runBenchmarks);
const auditMock = vi.mocked(api.runDosAudit);

beforeEach(() => {
  benchmarksMock.mockResolvedValue(makeBenchmarkResult());
  auditMock.mockResolvedValue(makeAuditResult());
});

describe('BenchmarksLab', () => {
  it('does not start expensive runs before an explicit action', () => {
    render(<BenchmarksLab />);
    expect(screen.getByRole('button', { name: 'Run 40-Case Benchmark' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Run DoS & Secret Audit' })).toBeInTheDocument();
    expect(screen.getByText('BENCHMARKS NOT RUN')).toBeInTheDocument();
    expect(benchmarksMock).not.toHaveBeenCalled();
    expect(auditMock).not.toHaveBeenCalled();
  });

  it('renders all six metrics, three policies and the eight-category matrix', async () => {
    const user = userEvent.setup();
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    render(<BenchmarksLab />);
    await user.click(screen.getByRole('button', { name: 'Run 40-Case Benchmark' }));

    const comparison = await screen.findByLabelText('Benchmark comparison');
    expect(comparison).toHaveTextContent('40 CASES');
    for (const label of ['Injection Block Rate', 'Content Token F1', 'Token Noise Reduction', 'Table Alignment Rate', 'P95 Latency', 'P99 Latency']) {
      expect(comparison).toHaveTextContent(label);
    }
    expect(comparison).toHaveTextContent('95.0%');
    expect(comparison).toHaveTextContent('97.0%');
    expect(comparison).toHaveTextContent('740 μs');
    expect(comparison).toHaveTextContent('920 μs');
    expect(comparison).toHaveTextContent('raw_upstream');
    expect(comparison).toHaveTextContent('clean_rag');
    expect(comparison).toHaveTextContent('strict_guard');

    const matrix = screen.getByLabelText('Eight-category benchmark matrix');
    for (const category of BENCHMARK_CATEGORIES) expect(matrix).toHaveTextContent(category);
    expect(consoleError).not.toHaveBeenCalled();
  });

  it('renders four independent security audit cards with observed details', async () => {
    const user = userEvent.setup();
    render(<BenchmarksLab />);
    await user.click(screen.getByRole('button', { name: 'Run DoS & Secret Audit' }));
    const audit = await screen.findByLabelText('DoS and secret redaction audit');
    expect(audit).toHaveTextContent('deep_dom_nesting');
    expect(audit).toHaveTextContent('oversized_html_bytes');
    expect(audit).toHaveTextContent('quadratic_ordered_list');
    expect(audit).toHaveTextContent('credential_redaction');
    expect(audit).toHaveTextContent('120 μs');
    expect(audit).toHaveTextContent('observed_depth');
    expect(audit).toHaveTextContent('max_depth');
    expect(audit).toHaveTextContent('PASS');
  });

  it('preserves zero-valued metrics instead of treating them as missing', async () => {
    const result = makeBenchmarkResult();
    result.modes.strict_guard = {
      ...result.modes.strict_guard!,
      injection_block_rate: 0,
      content_f1: 0,
      token_reduction_rate: 0,
      table_alignment_rate: 0,
      p95_us: 0,
      p99_us: 0,
    };
    benchmarksMock.mockResolvedValue(result);
    const user = userEvent.setup();
    render(<BenchmarksLab />);
    await user.click(screen.getByRole('button', { name: 'Run 40-Case Benchmark' }));
    const comparison = await screen.findByLabelText('Benchmark comparison');
    await waitFor(() => expect(comparison).toHaveTextContent('0.0%'));
    expect(comparison).toHaveTextContent('0 μs');
  });

  it('shows the sample counts when a category has no threats or tables', async () => {
    const result = makeBenchmarkResult();
    result.by_category.clean_article_preservation = Object.fromEntries(POLICIES.map((policy) => [policy, {
      ...result.modes[policy]!,
      case_count: 5,
      injection_count: 0,
      injection_block_rate: null,
      table_case_count: 0,
      table_alignment_rate: null,
    }]));
    benchmarksMock.mockResolvedValue(result);
    const user = userEvent.setup();
    render(<BenchmarksLab />);
    await user.click(screen.getByRole('button', { name: 'Run 40-Case Benchmark' }));
    const row = await screen.findByRole('row', { name: /clean_article_preservation/ });
    expect(within(row).getAllByText('N/A (0 cases)')).toHaveLength(6);
    expect(row).not.toHaveTextContent('100.0%');
  });

  it('keeps audit results when benchmarks fail and retries only the failed run', async () => {
    const user = userEvent.setup();
    benchmarksMock.mockRejectedValueOnce(new Error('benchmark budget exceeded'));
    render(<BenchmarksLab />);
    await user.click(screen.getByRole('button', { name: 'Run 40-Case Benchmark' }));
    await user.click(screen.getByRole('button', { name: 'Run DoS & Secret Audit' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('benchmark budget exceeded');
    expect(await screen.findByLabelText('DoS and secret redaction audit')).toHaveTextContent('deep_dom_nesting');
    await user.click(screen.getByRole('button', { name: 'Retry benchmarks' }));
    await waitFor(() => expect(benchmarksMock).toHaveBeenCalledTimes(2));
    expect(await screen.findByLabelText('Benchmark comparison')).toHaveTextContent('40 CASES');
    expect(auditMock).toHaveBeenCalledTimes(1);
  });
});
