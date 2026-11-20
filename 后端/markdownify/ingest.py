"""Auditable, offline HTML-to-Markdown ingestion."""

from collections import defaultdict
from dataclasses import dataclass
from time import perf_counter_ns
from typing import Literal

from bs4 import BeautifulSoup, Comment, Doctype, NavigableString, Tag

from . import ATX, MarkdownConverter
from .audit import AuditTrail, DomLocations, Operation, OutputProbe, ThreatFinding
from .baseline import (
    BASELINE_COMMIT,
    BASELINE_VERSION,
    BaselineResult,
    _convert_baseline_soup,
    guard_legacy_layout,
)
from .boilerplate import prune_dom
from .guard import parse_html, utf8_size
from .guard import redact_secrets as mask_secrets
from .metrics import reduction_rate, token_estimate
from .prompt_guard import guard_dom, rendered_probes
from .structural import check_slot_budget, markdown_table_metrics

IngestPolicy = Literal["raw_upstream", "clean_rag", "strict_guard"]
_CREDENTIAL_ATTRIBUTES = frozenset({"href", "src", "poster", "alt", "title", "data-lang", "data-language"})
__all__ = ["IngestPolicy", "IngestResult", "ingest_html", "token_estimate"]


@dataclass(frozen=True, slots=True)
class IngestResult:
    policy: IngestPolicy
    markdown: str
    input_bytes: int
    token_count: int
    token_reduction_rate: float | None
    operations: list[Operation]
    threats: list[ThreatFinding]
    table_alignment_valid: bool
    cells_expanded: int
    secrets_redacted: int
    confidence_score: float
    elapsed_us: int
    baseline: BaselineResult | None
    threats_blocked: int | None = None

    @property
    def threats_cleaned(self) -> int:
        return sum(threat.action != "flagged" for threat in self.threats)


def _redact_dom(root: Tag, locations: DomLocations, audit: AuditTrail) -> int:
    total = 0
    for node in list(root.descendants):
        if isinstance(node, Tag):
            for attr, value in node.attrs.items():
                if attr not in _CREDENTIAL_ATTRIBUTES or not isinstance(value, str):
                    continue
                masked, count = mask_secrets(value)
                if count:
                    node[attr] = masked
                    audit.operations.append(Operation(
                        "REDACT_SECRET", f"{locations.path(node)}/@{attr}", "Credential", count,
                    ))
                    total += count
        elif isinstance(node, NavigableString) and not isinstance(node, (Comment, Doctype)):
            masked, count = mask_secrets(str(node))
            if count:
                audit.operations.append(Operation("REDACT_SECRET", locations.path(node), "Credential", count))
                node.replace_with(type(node)(masked))
                total += count
    return total


def _inspect_upstream(
    soup: BeautifulSoup, audit: AuditTrail,
) -> tuple[str, list[tuple[ThreatFinding, OutputProbe]]]:
    if not audit.probes:
        return _convert_baseline_soup(soup), []

    by_scope: dict[int, list[tuple[ThreatFinding, OutputProbe]]] = defaultdict(list)
    for finding, probe in audit.probes:
        by_scope[id(probe.scope)].append((finding, probe))
    rendered_ids: set[str] = set()

    def observe(node: Tag, markdown: str) -> None:
        scoped = by_scope.get(id(node))
        if not scoped or not markdown:
            return
        occurrences = rendered_probes(markdown)
        for finding, probe in scoped:
            if occurrences[probe.key]:
                occurrences[probe.key] -= 1
                rendered_ids.add(finding.id)

    markdown = _convert_baseline_soup(soup, observe=observe)
    occurrences = rendered_probes(markdown)
    leaked = []
    for finding, probe in audit.probes:
        if finding.id in rendered_ids and occurrences[probe.key]:
            occurrences[probe.key] -= 1
            leaked.append((finding, probe))
    return markdown, leaked


def _confidence(audit: AuditTrail, aligned: bool) -> float:
    penalties = {"low": 0.05, "medium": 0.1, "high": 0.2, "critical": 0.3}
    residual_risk = sum(penalties[threat.severity] for threat in audit.threats if threat.action == "flagged")
    return round(max(0.0, (1.0 if aligned else 0.8) - residual_risk), 3)


def ingest_html(
    raw_html: str,
    *,
    policy: IngestPolicy = "strict_guard",
    strip_hidden: bool = True,
    prune_boilerplate: bool = True,
    normalize_tables: bool = True,
    clean_urls: bool = True,
    redact_secrets: bool = True,
    infer_code_language: bool = True,
    heading_style: str = ATX,
    compare_baseline: bool = False,
) -> IngestResult:
    """Convert HTML with source-relative audit records and optional upstream comparison.

    Raw mode and the opt-in baseline carry the upstream Markdown verbatim.
    """
    if policy not in ("raw_upstream", "clean_rag", "strict_guard"):
        raise ValueError("Unknown ingestion policy")
    start = perf_counter_ns()
    soup = parse_html(raw_html)
    input_bytes = utf8_size(raw_html)
    parsing_ns = perf_counter_ns() - start
    raw_mode = policy == "raw_upstream"
    audit = AuditTrail()
    locations = DomLocations(soup, lambda label: mask_secrets(label)[0])
    upstream_markdown = None
    baseline_work_ns = baseline_us = 0
    exposed: list[tuple[ThreatFinding, OutputProbe]] = []
    source_containers: list[int] = []
    if compare_baseline:
        baseline_start = perf_counter_ns()
        baseline_audit = audit if raw_mode else AuditTrail()
        guard_dom(soup, locations, baseline_audit, strip_hidden=False, strict=True, apply=False)
        snapshot_start = perf_counter_ns()
        upstream_markdown, exposed = _inspect_upstream(soup, baseline_audit)
        baseline_end = perf_counter_ns()
        source_containers = [
            baseline_audit.containers[finding.id]
            for finding, _ in exposed
        ]
        baseline_work_ns = perf_counter_ns() - baseline_start
        baseline_us = (parsing_ns + baseline_end - snapshot_start) // 1000
    elif raw_mode:
        upstream_markdown = _convert_baseline_soup(soup)

    if not (raw_mode and compare_baseline):
        guard_dom(
            soup, locations, audit, strip_hidden=strip_hidden, strict=policy != "clean_rag",
            apply=not raw_mode, clean_urls=clean_urls,
        )

    cells_expanded = total_slots = secrets_redacted = 0
    surviving_containers: set[int] = set()

    def observe_table(table: Tag, slots: int, expanded: int) -> None:
        nonlocal cells_expanded, total_slots
        total_slots += slots
        check_slot_budget(total_slots)
        cells_expanded += expanded
        if expanded:
            audit.operations.append(Operation("NORMALIZE_TABLE", locations.path(table), "Expanded spans", expanded))

    if raw_mode:
        assert upstream_markdown is not None
        markdown = upstream_markdown
    else:
        if prune_boilerplate:
            prune_dom(soup, locations, audit)
        if exposed or any(threat.action == "flagged" for threat in audit.threats):
            surviving_containers = {id(soup), *(id(tag) for tag in soup.find_all(True))}
            audit.mark_removed(surviving_containers)
        if redact_secrets:
            secrets_redacted = _redact_dom(soup, locations, audit)
        if not normalize_tables:
            guard_legacy_layout(soup)
        # The table observer accumulates render budgets per ingestion call.
        converter = MarkdownConverter(
            normalize_tables=normalize_tables, infer_code_language=infer_code_language,
            heading_style=heading_style, escape_misc=True,
        )
        converter.options["_table_observer"] = observe_table
        converter.options["_safe_markdown"] = True
        markdown = converter.convert_soup(soup)
        if redact_secrets:
            markdown, count = mask_secrets(markdown)
            if count:
                audit.operations.append(Operation("REDACT_SECRET", "/", "Rendered credential", count))
                secrets_redacted += count

    _, aligned = markdown_table_metrics(markdown)
    tokens = token_estimate(markdown)
    elapsed_ns = perf_counter_ns() - start
    elapsed_us = (elapsed_ns if raw_mode else elapsed_ns - baseline_work_ns) // 1000
    baseline = None
    reduction = None
    threats_blocked = None
    if compare_baseline and upstream_markdown is not None:
        upstream_tokens = token_estimate(upstream_markdown)
        _, upstream_aligned = markdown_table_metrics(upstream_markdown)
        leaked = [finding for finding, _ in exposed]
        baseline = BaselineResult(
            BASELINE_VERSION, BASELINE_COMMIT, upstream_markdown, upstream_tokens, len(leaked),
            leaked, upstream_aligned, baseline_us,
        )
        reduction = reduction_rate(upstream_tokens, tokens)
        threats_blocked = 0
        if exposed and not raw_mode:
            cleaned = {probe.position for finding, probe in audit.probes if finding.action != "flagged"}
            threats_blocked = sum(
                probe.position in cleaned or container not in surviving_containers
                for (_, probe), container in zip(exposed, source_containers, strict=True)
            )
    return IngestResult(
        policy, markdown, input_bytes, tokens, reduction, audit.operations, audit.threats,
        aligned, cells_expanded, secrets_redacted, _confidence(audit, aligned), elapsed_us, baseline, threats_blocked,
    )
