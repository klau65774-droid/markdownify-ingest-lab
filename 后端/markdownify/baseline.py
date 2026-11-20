"""Run the exact upstream 1.2.4 converter on bounded HTML inputs."""

from collections.abc import Callable
from dataclasses import dataclass

from bs4 import BeautifulSoup, Tag

from . import _upstream_v124
from .audit import ThreatFinding
from .guard import BudgetExceededError, HTMLInputError, parse_html
from .structural import check_slot_budget, span_width

BASELINE_VERSION = "1.2.4"
BASELINE_COMMIT = "dc6ad25"
_MAX_LEGACY_LIST_WORK = 2_500_000


@dataclass(frozen=True, slots=True)
class BaselineResult:
    version: str
    commit: str
    markdown: str
    token_count: int
    leaked_threat_count: int
    leaked_threats: list[ThreatFinding]
    table_alignment_valid: bool
    elapsed_us: int


def guard_legacy_layout(root: Tag, *, quadratic_lists: bool = False) -> None:
    """Bound output expansion and the upstream list's sibling-work estimate."""
    names = ["td", "th", "ol"] if quadratic_lists else ["td", "th"]
    table_slots = list_work = 0
    for node in root.find_all(names):
        if node.name != "ol":
            table_slots += span_width(node.get("colspan"), 1000)
            check_slot_budget(table_slots)
        else:
            # Upstream visits every preceding sibling, including text and
            # non-list tags, to find the preceding list items.
            for position, child in enumerate(node.contents):
                if isinstance(child, Tag) and child.name == "li":
                    list_work += position
                    if list_work > _MAX_LEGACY_LIST_WORK:
                        raise BudgetExceededError("max_nodes", _MAX_LEGACY_LIST_WORK, list_work)


class _ObservedConverter(_upstream_v124.MarkdownConverter):
    def __init__(self, observe: Callable[[Tag, str], None]) -> None:
        super().__init__()
        self._observe = observe

    def process_tag(self, node: Tag, parent_tags: set[str] | None = None) -> str:
        markdown: str = super().process_tag(node, parent_tags)
        self._observe(node, markdown)
        return markdown


def _convert_baseline_soup(
    root: BeautifulSoup, *, observe: Callable[[Tag, str], None] | None = None,
) -> str:
    guard_legacy_layout(root, quadratic_lists=True)
    try:
        converter = _upstream_v124.MarkdownConverter() if observe is None else _ObservedConverter(observe)
        return converter.convert_soup(root)
    except (ValueError, TypeError) as exc:
        raise HTMLInputError("Upstream converter rejected the input") from exc


def baseline_markdownify(raw_html: str) -> str:
    """Convert using the bundled snapshot and its original default options."""
    return _convert_baseline_soup(parse_html(raw_html))
