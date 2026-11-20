import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import { makeIngestResult, presets } from '../../test/fixtures';
import { IngestLab } from './IngestLab';

vi.mock('../../api/client', () => ({
  api: { presets: vi.fn(), ingest: vi.fn() },
}));

const presetsMock = vi.mocked(api.presets);
const ingestMock = vi.mocked(api.ingest);

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

beforeEach(() => {
  presetsMock.mockResolvedValue(presets);
  ingestMock.mockImplementation(async (request) => request.compare_baseline ? makeIngestResult() : makeIngestResult({
    baseline: null,
    threats_blocked: null,
    token_reduction_rate: null,
  }));
});

describe('IngestLab', () => {
  it('loads real presets, runs the first scenario and renders guard telemetry', async () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    render(<IngestLab />);

    expect(await screen.findByRole('button', { name: 'Zero-Width & Comment Jailbreak' })).toBeInTheDocument();
    await waitFor(() => expect(ingestMock).toHaveBeenCalledWith(expect.objectContaining({
      html: presets[0].html,
      policy: 'strict_guard',
      strip_hidden: true,
      prune_boilerplate: true,
      normalize_tables: true,
      clean_urls: true,
      redact_secrets: true,
      compare_baseline: false,
    })));
    expect(await screen.findByText('GUARD CHECKS PASSED')).toBeInTheDocument();
    expect(screen.getByLabelText('Sanitized agent Markdown')).toHaveTextContent('Q1–Q2 Reliability Report');
    expect(screen.getByText('BASELINE NOT REQUESTED')).toBeInTheDocument();
    expect(screen.getByLabelText('Ingestion findings')).toHaveTextContent(/Findings detected\s*4/);
    expect(screen.getByLabelText('Ingestion findings')).toHaveTextContent(/Cleaned in source\s*4/);
    expect(screen.getByLabelText('Ingestion findings')).toHaveTextContent(/Upstream leaks removed\s*—/);
    expect(screen.getByText('CHECKS PASSED')).toBeInTheDocument();
    expect(screen.getByText('420 μs')).toBeInTheDocument();
    expect(screen.getByText(/DOM SANITIZATION & PROMPT-INJECTION AUDIT TRACE \(7 OPS\)/)).toBeInTheDocument();
    expect(consoleError).not.toHaveBeenCalled();
  });

  it('loads a clicked preset and automatically runs its HTML', async () => {
    const user = userEvent.setup();
    render(<IngestLab />);
    const button = await screen.findByRole('button', { name: 'Complex Colspan/Rowspan Table' });
    await user.click(button);

    await waitFor(() => expect(ingestMock).toHaveBeenCalledTimes(2));
    expect(ingestMock).toHaveBeenLastCalledWith(expect.objectContaining({ html: presets[2].html }));
    expect(screen.getByLabelText('Raw untrusted HTML payload')).toHaveValue(presets[2].html);
    expect(button).toHaveAttribute('aria-pressed', 'true');
  });

  it('applies policy and feature toggles to the next ingest request', async () => {
    const user = userEvent.setup();
    render(<IngestLab />);
    await screen.findByText('GUARD CHECKS PASSED');

    await user.click(screen.getByRole('button', { name: 'Clean RAG' }));
    await user.click(screen.getByRole('switch', { name: 'Strip Hidden DOM / CSS Injection' }));
    await user.click(screen.getByRole('switch', { name: 'Prune Nav/Footer Boilerplate' }));
    await user.click(screen.getByRole('switch', { name: 'Normalize Span Tables' }));
    await user.click(screen.getByRole('switch', { name: 'Redact Secrets & Tracking URLs' }));
    await user.click(screen.getByRole('button', { name: 'Run Ingest & Guard' }));

    expect(ingestMock).toHaveBeenLastCalledWith(expect.objectContaining({
      policy: 'clean_rag',
      strip_hidden: false,
      prune_boilerplate: false,
      normalize_tables: false,
      clean_urls: false,
      redact_secrets: false,
      compare_baseline: false,
      infer_code_language: true,
      heading_style: 'atx',
    }));
  });

  it('requests unredacted output only for the explicit comparison of the current input', async () => {
    const user = userEvent.setup();
    render(<IngestLab />);
    await screen.findByText('GUARD CHECKS PASSED');
    const editor = screen.getByLabelText('Raw untrusted HTML payload');
    const html = '<p>New document</p>';
    await user.clear(editor);
    await user.type(editor, html);
    await user.click(screen.getByRole('button', { name: 'Run Ingest & Guard' }));
    expect(ingestMock).toHaveBeenLastCalledWith(expect.objectContaining({ html, compare_baseline: false }));
    await screen.findByText('GUARD CHECKS PASSED');

    await user.click(screen.getByRole('button', { name: 'View Unredacted Upstream Markdown' }));
    expect(ingestMock).toHaveBeenLastCalledWith(expect.objectContaining({ html, compare_baseline: true }));
    expect(await screen.findByText('UPSTREAM LEAKS DETECTED')).toBeInTheDocument();
    expect(screen.getByLabelText('Ingestion findings')).toHaveTextContent(/Upstream leaks removed\s*4/);

    await user.click(screen.getByRole('button', { name: 'Complex Colspan/Rowspan Table' }));
    expect(ingestMock).toHaveBeenLastCalledWith(expect.objectContaining({ html: presets[2].html, compare_baseline: false }));
    expect(screen.queryByText('UPSTREAM LEAKS DETECTED')).not.toBeInTheDocument();
    expect(await screen.findByText('BASELINE NOT REQUESTED')).toBeInTheDocument();
  });

  it('discards an unredacted response that arrives after editing the input', async () => {
    const user = userEvent.setup();
    render(<IngestLab />);
    await screen.findByText('GUARD CHECKS PASSED');
    const pending = deferred<ReturnType<typeof makeIngestResult>>();
    ingestMock.mockReturnValueOnce(pending.promise);
    await user.click(screen.getByRole('button', { name: 'View Unredacted Upstream Markdown' }));
    const editor = screen.getByLabelText('Raw untrusted HTML payload');
    await user.clear(editor);
    await user.type(editor, '<p>Different input</p>');
    await act(async () => {
      pending.resolve(makeIngestResult());
      await pending.promise;
    });
    expect(screen.queryByText('UPSTREAM LEAKS DETECTED')).not.toBeInTheDocument();
    expect(screen.getByText('BASELINE NOT REQUESTED')).toBeInTheDocument();
  });

  it('shows table misalignment and a missing baseline without fabricating values', async () => {
    ingestMock.mockResolvedValue(makeIngestResult({
      table_alignment_valid: false, baseline: null, token_reduction_rate: null, threats: [], threats_cleaned: 0, threats_blocked: null,
    }));
    render(<IngestLab />);
    expect(await screen.findByText('TABLE MISALIGNED')).toBeInTheDocument();
    expect(screen.getByText('BASELINE NOT REQUESTED')).toBeInTheDocument();
    expect(screen.getByText('N/A')).toBeInTheDocument();
    expect(screen.getByText('Misaligned')).toBeInTheDocument();
  });

  it('surfaces API errors and retries the same payload', async () => {
    const user = userEvent.setup();
    ingestMock.mockRejectedValueOnce(new Error('max_depth: observed 90 / limit 64'));
    render(<IngestLab />);
    expect(await screen.findByRole('alert')).toHaveTextContent('max_depth: observed 90 / limit 64');
    await user.click(screen.getByRole('button', { name: 'Retry connection' }));
    await waitFor(() => expect(ingestMock).toHaveBeenCalledTimes(2));
    expect(await screen.findByText('GUARD CHECKS PASSED')).toBeInTheDocument();
  });

  it('ignores a stale ingest response after a newer preset is selected', async () => {
    const first = deferred<ReturnType<typeof makeIngestResult>>();
    const second = deferred<ReturnType<typeof makeIngestResult>>();
    ingestMock.mockReset();
    ingestMock.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const user = userEvent.setup();
    render(<IngestLab />);
    const secondPreset = await screen.findByRole('button', { name: 'Zero-Width & Comment Jailbreak' });
    await user.click(secondPreset);

    await act(async () => {
      second.resolve(makeIngestResult({ markdown: '# NEWEST RESULT', token_count: 42, threats: [] }));
      await second.promise;
    });
    expect(await screen.findByText('GUARD CHECKS PASSED')).toBeInTheDocument();
    await act(async () => {
      first.resolve(makeIngestResult({ markdown: '# STALE RESULT', token_count: 999 }));
      await first.promise;
    });
    expect(screen.queryByText(/STALE RESULT/)).not.toBeInTheDocument();
    expect(screen.getByLabelText('Sanitized agent Markdown')).toHaveTextContent('NEWEST RESULT');
  });
});
