"""Request and response contracts for the eight workbench routes."""

from typing import Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from ..audit import Operation, Severity, ThreatFinding
from ..baseline import BaselineResult
from ..guard import BudgetCode
from ..ingest import IngestPolicy

MAX_BATCH_DOCUMENTS = 16


class _HtmlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    html: str = Field(validation_alias=AliasChoices("html", "raw_html"))


class IngestRequest(_HtmlRequest):
    policy: IngestPolicy = "strict_guard"
    strip_hidden: bool = True
    prune_boilerplate: bool = True
    normalize_tables: bool = True
    clean_urls: bool = True
    redact_secrets: bool = True
    infer_code_language: bool = True
    heading_style: Literal["atx", "atx_closed", "underlined"] = "atx"
    compare_baseline: bool = False

    @field_validator("heading_style", mode="before")
    @classmethod
    def normalize_heading_style(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.lower()
        return "underlined" if value == "setext" else value


class IngestResultModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    policy: IngestPolicy
    markdown: str
    input_bytes: int
    token_count: int
    token_reduction_rate: float | None
    operations: list[Operation]
    threats: list[ThreatFinding]
    threats_cleaned: int
    threats_blocked: int | None
    table_alignment_valid: bool
    cells_expanded: int
    secrets_redacted: int
    confidence_score: float = Field(ge=0, le=1)
    elapsed_us: int
    baseline: BaselineResult | None


class HealthResult(BaseModel):
    status: Literal["ok"] = "ok"
    version: str
    uptime_ms: int
    preset_count: int
    engine_capabilities: dict[str, bool]


class Preset(BaseModel):
    id: str
    title: str
    description: str
    html: str


class ThreatInspectRequest(_HtmlRequest):
    pass


RiskLevel = Literal["safe"] | Severity


class ThreatInspectResult(BaseModel):
    threats: list[ThreatFinding]
    leaked_in_upstream_count: int
    cleaned_in_enhanced_count: int
    blocked_in_enhanced_count: int
    risk_level: RiskLevel
    upstream_markdown_preview: str
    enhanced_markdown_preview: str
    elapsed_us: int


class TableNormalizeRequest(_HtmlRequest):
    pass


class TableNormalizeResult(BaseModel):
    upstream_table_markdown: str
    upstream_column_counts: list[int]
    upstream_aligned: bool
    normalized_table_markdown: str
    normalized_column_counts: list[int]
    normalized_aligned: bool
    cells_expanded: int


BenchmarkCategory = Literal[
    "hidden_css_injection", "zero_width_smuggling", "comment_and_attr_injection", "boilerplate_nav_bloat",
    "complex_span_tables", "code_language_fences", "tracking_and_malicious_urls", "clean_article_preservation",
]


class BenchmarkMetrics(BaseModel):
    case_count: int
    injection_count: int
    table_case_count: int
    injection_block_rate: float | None
    content_f1: float
    token_reduction_rate: float
    table_alignment_rate: float | None
    p95_us: int
    p99_us: int


class BenchmarkSample(BaseModel):
    case_id: str
    category: BenchmarkCategory
    mode: IngestPolicy
    injection_blocked: bool | None
    content_f1: float
    token_count: int
    table_alignment_valid: bool
    code_language_correct: bool | None
    elapsed_us: int
    markdown_preview: str


class BenchmarkResult(BaseModel):
    case_count: int
    modes: dict[IngestPolicy, BenchmarkMetrics]
    by_category: dict[BenchmarkCategory, dict[IngestPolicy, BenchmarkMetrics]]
    sample_results: list[BenchmarkSample]


AuditCheckName = Literal[
    "deep_dom_nesting", "oversized_html_bytes", "quadratic_ordered_list", "credential_redaction",
]


class AuditCheck(BaseModel):
    name: AuditCheckName
    status: Literal["PASS", "FAIL"]
    elapsed_us: int
    details: dict[str, str | int]


class AuditResult(BaseModel):
    status: Literal["PASS", "FAIL"]
    checks: list[AuditCheck]


class BatchDocInput(_HtmlRequest):
    id: str | None = Field(default=None, max_length=128)


class BatchPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    documents: list[BatchDocInput] = Field(max_length=MAX_BATCH_DOCUMENTS)
    policy: IngestPolicy = "strict_guard"


class BatchDocSummary(BaseModel):
    id: str
    token_count: int
    upstream_token_count: int
    token_reduction_rate: float
    threats_detected: int
    threats_cleaned: int
    threats_blocked: int
    table_alignment_valid: bool
    markdown_preview: str
    elapsed_us: int


class BatchPreviewResult(BaseModel):
    document_count: int
    token_count: int
    upstream_token_count: int
    token_reduction_rate: float
    threats_detected: int
    threats_cleaned: int
    threats_blocked: int
    documents: list[BatchDocSummary]


class BudgetErrorDetail(BaseModel):
    code: BudgetCode
    limit: int
    observed: int


class BudgetErrorResponse(BaseModel):
    detail: BudgetErrorDetail


class InvalidUTF8Detail(BaseModel):
    code: Literal["invalid_utf8"]


class InvalidUTF8Response(BaseModel):
    detail: InvalidUTF8Detail


class ValidationIssue(BaseModel):
    type: str
    loc: list[str | int]
    msg: str


class ValidationErrorResponse(BaseModel):
    detail: list[ValidationIssue]
