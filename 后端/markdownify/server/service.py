"""Transport-neutral workbench operations."""

from statistics import median
from time import perf_counter_ns

from .. import MarkdownConverter
from ..baseline import BaselineResult
from ..guard import (
    MAX_BYTES,
    BudgetCode,
    BudgetExceededError,
    redact_secrets,
    validate_html_budget,
)
from ..ingest import IngestResult, ingest_html
from ..metrics import reduction_rate
from ..structural import markdown_table_metrics
from .models import (
    AuditCheck,
    AuditCheckName,
    AuditResult,
    BatchDocSummary,
    BatchPreviewRequest,
    BatchPreviewResult,
    IngestRequest,
    IngestResultModel,
    RiskLevel,
    TableNormalizeResult,
    ThreatInspectResult,
)
from .presets import DEEP_DOM_HTML

_PREVIEW_LENGTH = 2048
_RISK: tuple[RiskLevel, ...] = ("safe", "low", "medium", "high", "critical")


def _preview(text: str) -> str:
    # Redact before truncating so a truncated credential cannot escape masking.
    return redact_secrets(text)[0][:_PREVIEW_LENGTH]


def _comparison(result: IngestResult) -> BaselineResult:
    assert result.baseline is not None
    return result.baseline


def ingest(request: IngestRequest) -> IngestResultModel:
    result = ingest_html(request.html, **request.model_dump(exclude={"html"}))
    return IngestResultModel.model_validate(result)


def threat_inspection(html: str) -> ThreatInspectResult:
    start = perf_counter_ns()
    result = ingest_html(html, compare_baseline=True)
    baseline = _comparison(result)
    assert result.threats_blocked is not None
    severities: list[RiskLevel] = ["safe", *(threat.severity for threat in result.threats)]
    risk = max(severities, key=_RISK.index)
    return ThreatInspectResult(
        threats=result.threats, leaked_in_upstream_count=baseline.leaked_threat_count,
        cleaned_in_enhanced_count=result.threats_cleaned,
        blocked_in_enhanced_count=result.threats_blocked, risk_level=risk,
        upstream_markdown_preview=_preview(baseline.markdown),
        enhanced_markdown_preview=_preview(result.markdown),
        elapsed_us=(perf_counter_ns() - start) // 1000,
    )


def table_normalization(html: str) -> TableNormalizeResult:
    result = ingest_html(html, policy="clean_rag", prune_boilerplate=False, compare_baseline=True)
    upstream = redact_secrets(_comparison(result).markdown)[0]
    raw_counts, raw_aligned = markdown_table_metrics(upstream)
    clean_counts, clean_aligned = markdown_table_metrics(result.markdown)
    return TableNormalizeResult(
        upstream_table_markdown=upstream, upstream_column_counts=raw_counts, upstream_aligned=raw_aligned,
        normalized_table_markdown=result.markdown, normalized_column_counts=clean_counts,
        normalized_aligned=clean_aligned, cells_expanded=result.cells_expanded,
    )


def batch_preview(request: BatchPreviewRequest) -> BatchPreviewResult:
    documents = []
    upstream_total = token_total = total_detected = total_cleaned = total_blocked = 0
    for index, document in enumerate(request.documents, start=1):
        result = ingest_html(document.html, policy=request.policy, compare_baseline=True)
        baseline = _comparison(result)
        assert result.threats_blocked is not None
        detected = len(result.threats)
        cleaned = result.threats_cleaned
        upstream_total += baseline.token_count
        token_total += result.token_count
        total_detected += detected
        total_cleaned += cleaned
        total_blocked += result.threats_blocked
        documents.append(BatchDocSummary(
            id=redact_secrets(document.id or f"doc-{index}")[0], token_count=result.token_count,
            upstream_token_count=baseline.token_count,
            token_reduction_rate=reduction_rate(baseline.token_count, result.token_count),
            threats_detected=detected, threats_cleaned=cleaned, threats_blocked=result.threats_blocked,
            table_alignment_valid=result.table_alignment_valid,
            markdown_preview=_preview(result.markdown), elapsed_us=result.elapsed_us,
        ))
    return BatchPreviewResult(
        document_count=len(documents), token_count=token_total, upstream_token_count=upstream_total,
        token_reduction_rate=reduction_rate(upstream_total, token_total),
        threats_detected=total_detected, threats_cleaned=total_cleaned,
        threats_blocked=total_blocked, documents=documents,
    )


def _check_rejection(name: AuditCheckName, html: str, expected: BudgetCode) -> AuditCheck:
    start = perf_counter_ns()
    try:
        validate_html_budget(html)
    except BudgetExceededError as error:
        return AuditCheck(
            name=name, status="PASS" if error.code == expected else "FAIL",
            elapsed_us=(perf_counter_ns() - start) // 1000,
            details={"code": error.code, "limit": error.limit, "observed": error.observed},
        )
    return AuditCheck(name=name, status="FAIL", elapsed_us=(perf_counter_ns() - start) // 1000, details={})


def _check_list() -> AuditCheck:
    html = "<ol>" + "<li>Item</li>" * 1500 + "</ol>"
    times = []
    for _ in range(3):
        start = perf_counter_ns()
        markdown = MarkdownConverter().convert(html)
        times.append((perf_counter_ns() - start) // 1000)
    elapsed_us = int(median(times))
    lines = markdown.splitlines()
    items = len(lines)
    correct = items == 1500 and lines[0] == "1. Item" and lines[-1] == "1500. Item"
    return AuditCheck(
        name="quadratic_ordered_list", status="PASS" if correct and elapsed_us < 50_000 else "FAIL",
        elapsed_us=elapsed_us, details={"item_count": items, "threshold_us": 50_000, "trials": len(times)},
    )


def credential_samples() -> tuple[str, ...]:
    """Deterministic, non-issued samples for all 15 credential rules."""
    return (
        "AKIA" + "X" * 16, "LTAI" + "X" * 16, "ghp_" + "X" * 20, "github_pat_" + "X" * 22,
        "sk-" + "X" * 20, "sk-ant-" + "X" * 20, "sk_test_" + "X" * 20, "rk_test_" + "X" * 20,
        "xoxb-" + "X" * 20, "AIza" + "X" * 35, "hf_" + "X" * 20,
        "Bearer " + "X1" * 10, "eyJ" + "X" * 8 + ".eyJ" + "X" * 8 + "." + "X" * 12,
        "postgresql://fixture:synthetic@localhost/db", "+86 13900000000",
    )


def _check_credentials() -> AuditCheck:
    samples = credential_samples()
    start = perf_counter_ns()
    result = ingest_html("<pre>" + "\n".join(samples) + "</pre>")
    elapsed_us = (perf_counter_ns() - start) // 1000
    plaintext = sum(sample in result.markdown for sample in samples)
    return AuditCheck(
        name="credential_redaction",
        status="PASS" if plaintext == 0 and result.secrets_redacted == len(samples) else "FAIL",
        elapsed_us=elapsed_us, details={"plaintext_matches": plaintext, "secrets_redacted": result.secrets_redacted},
    )


def run_dos_audit() -> AuditResult:
    checks = [
        _check_rejection("deep_dom_nesting", DEEP_DOM_HTML, "max_depth"),
        _check_rejection("oversized_html_bytes", "<p>" + "界" * (MAX_BYTES // 3 + 1) + "</p>", "max_bytes"),
        _check_list(),
        _check_credentials(),
    ]
    return AuditResult(status="PASS" if all(check.status == "PASS" for check in checks) else "FAIL", checks=checks)
