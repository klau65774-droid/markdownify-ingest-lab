import {
  AUDIT_CHECK_NAMES,
  AUDIT_STATUSES,
  BENCHMARK_CATEGORIES,
  BUDGET_CODES,
  HEADING_STYLES,
  OPERATION_KINDS,
  POLICIES,
  SEVERITIES,
  THREAT_ACTIONS,
  THREAT_CATEGORIES,
} from './types';

export {
  AUDIT_CHECK_NAMES,
  AUDIT_STATUSES,
  BENCHMARK_CATEGORIES,
  BUDGET_CODES,
  HEADING_STYLES,
  OPERATION_KINDS,
  POLICIES,
  SEVERITIES,
  THREAT_ACTIONS,
  THREAT_CATEGORIES,
};

export type EndpointContract = {
  path: string;
  method: 'GET' | 'POST';
  responseSchema: string;
  responseArray?: boolean;
  requestSchema?: string;
  errorStatuses: readonly string[];
};

export const API_CONTRACT: readonly EndpointContract[] = [
  { path: '/api/health', method: 'GET', responseSchema: 'HealthResult', errorStatuses: [] },
  { path: '/api/presets', method: 'GET', responseSchema: 'Preset', responseArray: true, errorStatuses: [] },
  { path: '/api/ingest', method: 'POST', requestSchema: 'IngestRequest', responseSchema: 'IngestResultModel', errorStatuses: ['400', '413', '422'] },
  { path: '/api/inspect/threats', method: 'POST', requestSchema: 'ThreatInspectRequest', responseSchema: 'ThreatInspectResult', errorStatuses: ['400', '413', '422'] },
  { path: '/api/tables/normalize', method: 'POST', requestSchema: 'TableNormalizeRequest', responseSchema: 'TableNormalizeResult', errorStatuses: ['400', '413', '422'] },
  { path: '/api/benchmarks/run', method: 'POST', responseSchema: 'BenchmarkResult', errorStatuses: ['400', '413', '422'] },
  { path: '/api/dos/audit', method: 'POST', responseSchema: 'AuditResult', errorStatuses: ['400', '413', '422'] },
  { path: '/api/batch/preview', method: 'POST', requestSchema: 'BatchPreviewRequest', responseSchema: 'BatchPreviewResult', errorStatuses: ['400', '413', '422'] },
];

export const SCHEMA_CONTRACT = {
  AuditCheck: { required: ['name', 'status', 'elapsed_us', 'details'] },
  AuditResult: { required: ['status', 'checks'] },
  BaselineResult: { required: ['version', 'commit', 'markdown', 'token_count', 'leaked_threat_count', 'leaked_threats', 'table_alignment_valid', 'elapsed_us'] },
  BatchDocInput: { required: ['html'] },
  BatchDocSummary: { required: ['id', 'token_count', 'upstream_token_count', 'token_reduction_rate', 'threats_detected', 'threats_cleaned', 'threats_blocked', 'table_alignment_valid', 'markdown_preview', 'elapsed_us'] },
  BatchPreviewRequest: { required: ['documents'] },
  BatchPreviewResult: { required: ['document_count', 'token_count', 'upstream_token_count', 'token_reduction_rate', 'threats_detected', 'threats_cleaned', 'threats_blocked', 'documents'] },
  BenchmarkMetrics: { required: ['case_count', 'injection_count', 'table_case_count', 'injection_block_rate', 'content_f1', 'token_reduction_rate', 'table_alignment_rate', 'p95_us', 'p99_us'] },
  BenchmarkResult: { required: ['case_count', 'modes', 'by_category', 'sample_results'] },
  BenchmarkSample: { required: ['case_id', 'category', 'mode', 'injection_blocked', 'content_f1', 'token_count', 'table_alignment_valid', 'code_language_correct', 'elapsed_us', 'markdown_preview'] },
  BudgetErrorDetail: { required: ['code', 'limit', 'observed'] },
  BudgetErrorResponse: { required: ['detail'] },
  HealthResult: { required: ['version', 'uptime_ms', 'preset_count', 'engine_capabilities'] },
  IngestRequest: { required: ['html'] },
  IngestResultModel: { required: ['policy', 'markdown', 'input_bytes', 'token_count', 'token_reduction_rate', 'operations', 'threats', 'threats_cleaned', 'threats_blocked', 'table_alignment_valid', 'cells_expanded', 'secrets_redacted', 'confidence_score', 'elapsed_us', 'baseline'] },
  InvalidUTF8Detail: { required: ['code'] },
  InvalidUTF8Response: { required: ['detail'] },
  Operation: { required: ['kind', 'dom_path', 'detail'] },
  Preset: { required: ['id', 'title', 'description', 'html'] },
  TableNormalizeRequest: { required: ['html'] },
  TableNormalizeResult: { required: ['upstream_table_markdown', 'upstream_column_counts', 'upstream_aligned', 'normalized_table_markdown', 'normalized_column_counts', 'normalized_aligned', 'cells_expanded'] },
  ThreatFinding: { required: ['id', 'category', 'severity', 'dom_path', 'snippet', 'action'] },
  ThreatInspectRequest: { required: ['html'] },
  ThreatInspectResult: { required: ['threats', 'leaked_in_upstream_count', 'cleaned_in_enhanced_count', 'blocked_in_enhanced_count', 'risk_level', 'upstream_markdown_preview', 'enhanced_markdown_preview', 'elapsed_us'] },
  ValidationErrorResponse: { required: ['detail'] },
  ValidationIssue: { required: ['type', 'loc', 'msg'] },
} as const;

export const ENUM_CONTRACT = {
  'AuditCheck.name': AUDIT_CHECK_NAMES,
  'AuditCheck.status': AUDIT_STATUSES,
  'AuditResult.status': AUDIT_STATUSES,
  'BatchPreviewRequest.policy': POLICIES,
  'BenchmarkSample.category': BENCHMARK_CATEGORIES,
  'BenchmarkSample.mode': POLICIES,
  'BudgetErrorDetail.code': BUDGET_CODES,
  'HealthResult.status': ['ok'],
  'IngestRequest.heading_style': HEADING_STYLES,
  'IngestRequest.policy': POLICIES,
  'IngestResultModel.policy': POLICIES,
  'InvalidUTF8Detail.code': ['invalid_utf8'],
  'Operation.kind': OPERATION_KINDS,
  'ThreatFinding.action': THREAT_ACTIONS,
  'ThreatFinding.category': THREAT_CATEGORIES,
  'ThreatFinding.severity': SEVERITIES,
  'ThreatInspectResult.risk_level': ['safe', ...SEVERITIES],
} as const;
