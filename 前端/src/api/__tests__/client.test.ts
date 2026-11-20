import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api } from '../client';
import type { BatchPreviewRequest, IngestRequest } from '../types';

const fetchMock = vi.fn<typeof fetch>();

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock);
});

describe('api client', () => {
  it('measures health round-trip latency and returns the health payload', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ version: '1.2.4', uptime_ms: 8, preset_count: 6, engine_capabilities: {} }));
    const result = await api.health();
    expect(result.data.version).toBe('1.2.4');
    expect(result.latencyMs).toEqual(expect.any(Number));
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
    expect(fetchMock).toHaveBeenCalledWith('/api/health', expect.objectContaining({ method: 'GET' }));
  });

  it('loads presets and posts the complete ingest body', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([])).mockResolvedValueOnce(jsonResponse({ markdown: '# Safe' }));
    await api.presets();
    const input: IngestRequest = {
      html: '<h1>Safe</h1>',
      policy: 'strict_guard',
      strip_hidden: true,
      prune_boilerplate: true,
      normalize_tables: true,
      clean_urls: true,
      redact_secrets: true,
      infer_code_language: true,
      heading_style: 'atx',
      compare_baseline: true,
    };
    await api.ingest(input);
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/presets', expect.objectContaining({ method: 'GET' }));
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/ingest', expect.objectContaining({ method: 'POST', body: JSON.stringify(input) }));
  });

  it('uses the exact threat and table request schemas', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse({})));
    await api.inspectThreats('<span>attack</span>');
    await api.normalizeTable('<table></table>');
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/inspect/threats', expect.objectContaining({ method: 'POST', body: JSON.stringify({ html: '<span>attack</span>' }) }));
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/tables/normalize', expect.objectContaining({ method: 'POST', body: JSON.stringify({ html: '<table></table>' }) }));
  });

  it('runs bodyless benchmark and DoS POST endpoints', async () => {
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse({})));
    await api.runBenchmarks();
    await api.runDosAudit();
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/benchmarks/run', expect.objectContaining({ method: 'POST' }));
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/dos/audit', expect.objectContaining({ method: 'POST' }));
    expect(fetchMock.mock.calls[0][1]?.body).toBeUndefined();
    expect(fetchMock.mock.calls[1][1]?.body).toBeUndefined();
  });

  it('posts batch preview documents', async () => {
    fetchMock.mockResolvedValue(jsonResponse({}));
    const input: BatchPreviewRequest = { documents: [{ id: 'a', html: '<p>A</p>' }], policy: 'clean_rag' };
    await api.batchPreview(input);
    expect(fetchMock).toHaveBeenCalledWith('/api/batch/preview', expect.objectContaining({ method: 'POST', body: JSON.stringify(input) }));
  });

  it('throws a structured ApiError using string detail', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ detail: 'Budget exceeded' }, 413));
    const promise = api.runBenchmarks();
    await expect(promise).rejects.toBeInstanceOf(ApiError);
    await expect(promise).rejects.toMatchObject({ status: 413, message: 'Budget exceeded' });
  });

  it('serializes structured error detail and handles non-JSON responses', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ detail: { code: 'max_depth', limit: 64, observed: 90 } }, 413));
    await expect(api.runDosAudit()).rejects.toMatchObject({ message: 'max_depth: observed 90 / limit 64', code: 'max_depth' });

    fetchMock.mockResolvedValueOnce(new Response('upstream unavailable', { status: 502 }));
    await expect(api.health()).rejects.toMatchObject({ status: 502, message: 'upstream unavailable' });
  });

  it('throws a useful error when the network is unavailable', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));
    await expect(api.presets()).rejects.toThrow('Failed to fetch');
  });
});
