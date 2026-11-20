export const POLICIES = ['raw_upstream', 'clean_rag', 'strict_guard'] as const;
export const HEADING_STYLES = ['atx', 'atx_closed', 'underlined'] as const;
export const OPERATION_KINDS = [
  'STRIP_DANGEROUS_URI',
  'STRIP_TRACKING_PIXEL',
  'CLEAN_TRACKING_URL',
  'STRIP_HIDDEN_STYLE',
  'STRIP_HIDDEN_ATTR',
  'STRIP_ZERO_WIDTH',
  'STRIP_SUSPICIOUS_ATTRIBUTE',
  'STRIP_INSTRUCTION',
  'PRUNE_BOILERPLATE',
  'REDACT_SECRET',
  'NORMALIZE_TABLE',
] as const;
export const THREAT_CATEGORIES = [
  'hidden_dom',
  'zero_width',
  'comment_injection',
  'attribute_injection',
  'instruction_override',
  'exfiltration_uri',
] as const;
export const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export const THREAT_ACTIONS = ['stripped', 'sanitized', 'flagged'] as const;
export const AUDIT_CHECK_NAMES = [
  'deep_dom_nesting',
  'oversized_html_bytes',
  'quadratic_ordered_list',
  'credential_redaction',
] as const;
export const AUDIT_STATUSES = ['PASS', 'FAIL'] as const;
export const BENCHMARK_CATEGORIES = [
  'hidden_css_injection',
  'zero_width_smuggling',
  'comment_and_attr_injection',
  'boilerplate_nav_bloat',
  'complex_span_tables',
  'code_language_fences',
  'tracking_and_malicious_urls',
  'clean_article_preservation',
] as const;
export const BUDGET_CODES = ['max_bytes', 'max_depth', 'max_nodes'] as const;

export type Policy = (typeof POLICIES)[number];
export type HeadingStyle = (typeof HEADING_STYLES)[number];
export type OperationKind = (typeof OPERATION_KINDS)[number];
export type ThreatCategory = (typeof THREAT_CATEGORIES)[number];
export type Severity = (typeof SEVERITIES)[number];
export type ThreatAction = (typeof THREAT_ACTIONS)[number];
export type AuditCheckName = (typeof AUDIT_CHECK_NAMES)[number];
export type AuditStatus = (typeof AUDIT_STATUSES)[number];
export type BenchmarkCategory = (typeof BENCHMARK_CATEGORIES)[number];

export interface HealthResult {
  status?: 'ok';
  version: string;
  uptime_ms: number;
  preset_count: number;
  engine_capabilities: Record<string, boolean>;
}

export interface HealthCheck {
  data: HealthResult;
  latencyMs: number;
}

export interface Preset {
  id: string;
  title: string;
  description: string;
  html: string;
}

export interface IngestRequest {
  html: string;
  policy?: Policy;
  strip_hidden?: boolean;
  prune_boilerplate?: boolean;
  normalize_tables?: boolean;
  clean_urls?: boolean;
  redact_secrets?: boolean;
  infer_code_language?: boolean;
  heading_style?: HeadingStyle;
  compare_baseline?: boolean;
}

export interface ThreatFinding {
  id: string;
  category: ThreatCategory;
  severity: Severity;
  dom_path: string;
  snippet: string;
  action: ThreatAction;
}

export interface Operation {
  kind: OperationKind;
  dom_path: string;
  detail: string;
  count?: number;
  tokens_saved?: number;
}

export interface BaselineResult {
  version: string;
  commit: string;
  markdown: string;
  token_count: number;
  leaked_threat_count: number;
  leaked_threats: ThreatFinding[];
  table_alignment_valid: boolean;
  elapsed_us: number;
}

export interface IngestResultModel {
  policy: Policy;
  markdown: string;
  input_bytes: number;
  token_count: number;
  token_reduction_rate: number | null;
  operations: Operation[];
  threats: ThreatFinding[];
  threats_cleaned: number;
  threats_blocked: number | null;
  table_alignment_valid: boolean;
  cells_expanded: number;
  secrets_redacted: number;
  confidence_score: number;
  elapsed_us: number;
  baseline: BaselineResult | null;
}

export interface ThreatInspectRequest {
  html: string;
}

export interface ThreatInspectResult {
  threats: ThreatFinding[];
  leaked_in_upstream_count: number;
  cleaned_in_enhanced_count: number;
  blocked_in_enhanced_count: number;
  risk_level: 'safe' | Severity;
  upstream_markdown_preview: string;
  enhanced_markdown_preview: string;
  elapsed_us: number;
}

export interface TableNormalizeRequest {
  html: string;
}

export interface TableNormalizeResult {
  upstream_table_markdown: string;
  upstream_column_counts: number[];
  upstream_aligned: boolean;
  normalized_table_markdown: string;
  normalized_column_counts: number[];
  normalized_aligned: boolean;
  cells_expanded: number;
}

export interface BenchmarkMetrics {
  case_count: number;
  injection_count: number;
  table_case_count: number;
  injection_block_rate: number | null;
  content_f1: number;
  token_reduction_rate: number;
  table_alignment_rate: number | null;
  p95_us: number;
  p99_us: number;
}

export interface BenchmarkSample {
  case_id: string;
  category: BenchmarkCategory;
  mode: Policy;
  injection_blocked: boolean | null;
  content_f1: number;
  token_count: number;
  table_alignment_valid: boolean;
  code_language_correct: boolean | null;
  elapsed_us: number;
  markdown_preview: string;
}

export interface BenchmarkResult {
  case_count: number;
  modes: Partial<Record<Policy, BenchmarkMetrics>>;
  by_category: Partial<Record<BenchmarkCategory, Partial<Record<Policy, BenchmarkMetrics>>>>;
  sample_results: BenchmarkSample[];
}

export interface AuditCheck {
  name: AuditCheckName;
  status: AuditStatus;
  elapsed_us: number;
  details: Record<string, string | number>;
}

export interface AuditResult {
  status: AuditStatus;
  checks: AuditCheck[];
}

export interface BatchDocInput {
  html: string;
  id?: string | null;
}

export interface BatchPreviewRequest {
  documents: BatchDocInput[];
  policy?: Policy;
}

export interface BatchDocSummary {
  id: string;
  token_count: number;
  upstream_token_count: number;
  token_reduction_rate: number;
  threats_detected: number;
  threats_cleaned: number;
  threats_blocked: number;
  table_alignment_valid: boolean;
  markdown_preview: string;
  elapsed_us: number;
}

export interface BatchPreviewResult {
  document_count: number;
  token_count: number;
  upstream_token_count: number;
  token_reduction_rate: number;
  threats_detected: number;
  threats_cleaned: number;
  threats_blocked: number;
  documents: BatchDocSummary[];
}

export interface InvalidUTF8Detail {
  code: 'invalid_utf8';
}

export interface InvalidUTF8Response {
  detail: InvalidUTF8Detail;
}

export interface BudgetErrorDetail {
  code: (typeof BUDGET_CODES)[number];
  limit: number;
  observed: number;
}

export interface BudgetErrorResponse {
  detail: BudgetErrorDetail;
}

export interface ValidationIssue {
  type: string;
  loc: (string | number)[];
  msg: string;
}

export interface ValidationErrorResponse {
  detail: ValidationIssue[];
}
