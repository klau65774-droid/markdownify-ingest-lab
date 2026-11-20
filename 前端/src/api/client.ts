import type {
  AuditResult,
  BatchPreviewRequest,
  BatchPreviewResult,
  BenchmarkResult,
  HealthCheck,
  IngestRequest,
  IngestResultModel,
  Preset,
  TableNormalizeResult,
  ThreatInspectResult,
} from './types';

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly payload?: unknown;

  constructor(message: string, status: number, code?: string, payload?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.payload = payload;
  }
}

type RequestOptions = {
  method: 'GET' | 'POST';
  body?: unknown;
};

function errorMessage(payload: unknown, status: number): { message: string; code?: string } {
  if (typeof payload === 'object' && payload !== null && 'detail' in payload) {
    const detail = payload.detail;
    if (typeof detail === 'string') return { message: detail };
    if (Array.isArray(detail)) {
      const messages = detail.map((issue) =>
        typeof issue === 'object' && issue !== null && 'msg' in issue
          ? String(issue.msg)
          : JSON.stringify(issue),
      );
      return { message: messages.join('; ') };
    }
    if (typeof detail === 'object' && detail !== null && 'code' in detail) {
      const code = String(detail.code);
      if ('observed' in detail && 'limit' in detail) {
        return {
          message: `${code}: observed ${String(detail.observed)} / limit ${String(detail.limit)}`,
          code,
        };
      }
      return { message: code, code };
    }
    return { message: JSON.stringify(detail) };
  }
  if (typeof payload === 'string' && payload.trim()) return { message: payload };
  return { message: `Ingest engine request failed (${status})` };
}

async function request<T>(path: string, { method, body }: RequestOptions): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: {
      Accept: 'application/json',
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      if (response.ok) throw new ApiError('Ingest engine returned invalid JSON', response.status);
      payload = text;
    }
  }
  if (!response.ok) {
    const { message, code } = errorMessage(payload, response.status);
    throw new ApiError(message, response.status, code, payload);
  }
  return payload as T;
}

export const api = {
  async health(): Promise<HealthCheck> {
    const startedAt = performance.now();
    const data = await request<HealthCheck['data']>('/api/health', { method: 'GET' });
    return { data, latencyMs: performance.now() - startedAt };
  },
  presets(): Promise<Preset[]> {
    return request('/api/presets', { method: 'GET' });
  },
  ingest(input: IngestRequest): Promise<IngestResultModel> {
    return request('/api/ingest', { method: 'POST', body: input });
  },
  inspectThreats(html: string): Promise<ThreatInspectResult> {
    return request('/api/inspect/threats', { method: 'POST', body: { html } });
  },
  normalizeTable(html: string): Promise<TableNormalizeResult> {
    return request('/api/tables/normalize', { method: 'POST', body: { html } });
  },
  runBenchmarks(): Promise<BenchmarkResult> {
    return request('/api/benchmarks/run', { method: 'POST' });
  },
  runDosAudit(): Promise<AuditResult> {
    return request('/api/dos/audit', { method: 'POST' });
  },
  batchPreview(input: BatchPreviewRequest): Promise<BatchPreviewResult> {
    return request('/api/batch/preview', { method: 'POST', body: input });
  },
};
