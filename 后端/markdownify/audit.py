"""Audit records with stable, source-relative DOM locations."""

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Literal

from bs4 import Comment, Tag
from bs4.element import PageElement

OperationKind = Literal[
    "STRIP_DANGEROUS_URI", "STRIP_TRACKING_PIXEL", "CLEAN_TRACKING_URL",
    "STRIP_HIDDEN_STYLE", "STRIP_HIDDEN_ATTR", "STRIP_ZERO_WIDTH",
    "STRIP_SUSPICIOUS_ATTRIBUTE", "STRIP_INSTRUCTION", "PRUNE_BOILERPLATE",
    "REDACT_SECRET", "NORMALIZE_TABLE",
]
ThreatCategory = Literal[
    "hidden_dom", "zero_width", "comment_injection", "attribute_injection",
    "instruction_override", "exfiltration_uri",
]
Severity = Literal["low", "medium", "high", "critical"]
Action = Literal["stripped", "sanitized", "flagged"]


@dataclass(frozen=True, slots=True)
class Operation:
    kind: OperationKind
    dom_path: str
    detail: str
    count: int = 1
    tokens_saved: int = 0


@dataclass(frozen=True, slots=True)
class ThreatFinding:
    id: str
    category: ThreatCategory
    severity: Severity
    dom_path: str
    snippet: str
    action: Action


@dataclass(frozen=True, slots=True)
class OutputProbe:
    """An occurrence in the source DOM and the tag whose rendering can expose it."""

    source: PageElement
    scope: Tag
    key: str
    attribute: str = ""
    offset: int = 0

    @property
    def position(self) -> tuple[int, str, int, str]:
        return id(self.source), self.attribute, self.offset, self.key


class DomLocations:
    """Index sibling ordinals once, before any guards mutate the tree."""

    def __init__(self, root: Tag, redact_label: Callable[[str], str]) -> None:
        self._parts: dict[int, tuple[Tag, str]] = {}
        labels: dict[str, str] = {}
        for node in (root, *root.find_all(True)):
            siblings: dict[str, int] = {}
            for child in node.contents:
                if isinstance(child, Tag):
                    name = child.name
                else:
                    name = "comment()" if isinstance(child, Comment) else "text()"
                ordinal = siblings.get(name, 0) + 1
                siblings[name] = ordinal
                if name not in labels:
                    label = redact_label(name)
                    labels[name] = label if len(label) <= 32 else label[:29] + "..."
                self._parts[id(child)] = (node, f"{labels[name]}[{ordinal}]")

    def path(self, node: PageElement) -> str:
        parts: list[str] = []
        while location := self._parts.get(id(node)):
            node, part = location
            parts.append(part)
        return "/" + "/".join(reversed(parts))

    def relocate(self, original: PageElement, replacement: PageElement) -> None:
        if location := self._parts.get(id(original)):
            self._parts[id(replacement)] = location


@dataclass(slots=True)
class AuditTrail:
    operations: list[Operation] = field(default_factory=list)
    threats: list[ThreatFinding] = field(default_factory=list)
    probes: list[tuple[ThreatFinding, OutputProbe]] = field(default_factory=list)
    containers: dict[str, int] = field(default_factory=dict)

    def finding(
        self, category: ThreatCategory, severity: Severity, path: str,
        snippet: str, action: Action, *, source: PageElement, probe: OutputProbe | None = None,
    ) -> None:
        finding = ThreatFinding(
            f"T{len(self.threats) + 1:03}", category, severity, path, snippet, action,
        )
        self.threats.append(finding)
        self.containers[finding.id] = id(source if isinstance(source, Tag) else source.parent)
        if probe is not None:
            self.probes.append((finding, probe))

    def mark_removed(self, surviving_containers: set[int]) -> None:
        """Record findings removed along with a source container during DOM cleanup."""
        removed = {
            finding.id: replace(finding, action="stripped")
            for finding in self.threats
            if finding.action == "flagged" and self.containers[finding.id] not in surviving_containers
        }
        if removed:
            self.threats[:] = [removed.get(finding.id, finding) for finding in self.threats]
            self.probes[:] = [(removed.get(finding.id, finding), probe) for finding, probe in self.probes]
