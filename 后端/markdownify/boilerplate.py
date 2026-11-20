"""Prune navigation and other chrome using bottom-up text/link statistics."""

import re
from dataclasses import dataclass

from bs4 import Comment, Doctype, NavigableString, Tag

from .audit import AuditTrail, DomLocations, Operation
from .metrics import token_estimate

_CHROME_TAGS = frozenset({
    "nav", "footer", "aside", "dialog", "svg", "canvas", "button",
    "select", "option", "datalist", "menuitem",
})
_CHROME_ROLES = frozenset({
    "navigation", "banner", "contentinfo", "complementary", "search", "menubar", "toolbar", "alertdialog",
})
_CHROME_TOKEN = re.compile(
    r"(?<![a-z0-9])(?:cookie|consent|gdpr|navbar|nav-bar|site-header|site-footer|sidebar|side-bar|"
    r"breadcrumbs?|pagination|share-buttons|social-share|newsletter|ad-slot|advert(?:isement)?|"
    r"promo-banner|popup|modal|related-posts|comments-section)(?![a-z0-9])", re.IGNORECASE,
)
_POSITIVE_CONTENT_TOKEN = re.compile(
    r"(?<![a-z0-9])(?:article(?:[-_]?body)?|entry[-_]?content|post[-_]?content|"
    r"page[-_]?content|main[-_]?content|story[-_]?body)(?![a-z0-9])",
    re.IGNORECASE,
)
_LAYOUT_MODIFIER_TOKEN = re.compile(
    r"^(?:.*(?:with|has|no|w|one|two|left|right)[-_]sidebar.*|"
    r".*sidebar[-_](?:fixed|enabled|left|right|first|second|layout).*|.*modal[-_]enabled.*)$",
    re.IGNORECASE,
)
_CONTENT_TAGS = frozenset({"article", "main"})
_DENSITY_CONTAINERS = frozenset({"div", "section", "ul", "ol", "menu"})
_DENSITY_PROTECTED = frozenset({"h1", "h2", "pre", "table"})


@dataclass(slots=True)
class _Stats:
    text: int = 0
    link_text: int = 0
    tokens: int = 0
    p_text: int = 0
    p_count: int = 0
    has_main: bool = False
    has_structure: bool = False


def _is_content(tag: Tag) -> bool:
    return tag.name in _CONTENT_TAGS or "main" in str(tag.get("role", "")).lower().split()


def _measure(root: Tag) -> dict[int, _Stats]:
    metrics: dict[int, _Stats] = {}
    for tag in reversed(root.find_all(True)):
        stats = _Stats(has_main=_is_content(tag))
        stats.has_structure = tag.name in _DENSITY_PROTECTED
        for child in tag.contents:
            if isinstance(child, Tag):
                nested = metrics[id(child)]
                stats.text += nested.text
                stats.link_text += nested.link_text
                stats.tokens += nested.tokens
                stats.p_text += nested.p_text
                stats.p_count += nested.p_count
                stats.has_main |= nested.has_main
                stats.has_structure |= nested.has_structure
            elif isinstance(child, NavigableString) and not isinstance(child, (Comment, Doctype)):
                text = child.strip()
                stats.text += len(text)
                stats.tokens += token_estimate(text)
        if tag.name == "a":
            stats.link_text = stats.text
        elif tag.name == "p":
            prose = max(0, stats.text - stats.link_text)
            stats.p_text = max(stats.p_text, prose)
            if prose >= 40:
                stats.p_count = max(stats.p_count, 1)
        metrics[id(tag)] = stats
    return metrics


def _has_chrome_class_or_id(tag: Tag) -> bool:
    class_names = tag.get("class", "")
    if isinstance(class_names, list):
        class_names = " ".join(class_names)
    combined = f"{class_names} {tag.get('id', '')}".strip()
    if not combined or _POSITIVE_CONTENT_TOKEN.search(combined):
        return False
    return any(
        _CHROME_TOKEN.search(token) and not _LAYOUT_MODIFIER_TOKEN.match(token)
        for token in combined.split()
    )


def _is_prose_container(stats: _Stats, total_p_text: int) -> bool:
    divisor = max(1, stats.text)
    if stats.p_count >= 3 and stats.link_text * 100 <= 45 * divisor:
        return True
    if stats.p_text >= 600 and stats.link_text * 100 <= 40 * divisor:
        return True
    return (
        total_p_text >= 400
        and stats.p_text * 100 >= 55 * total_p_text
        and stats.link_text * 100 <= 50 * divisor
    )


def _reason(tag: Tag, stats: _Stats, inside_article: bool, total_p_text: int) -> str | None:
    if stats.has_main or tag.name in {"html", "body"}:
        return None
    if tag.name in _CHROME_TAGS:
        return "Chrome element"
    prose_rich = _is_prose_container(stats, total_p_text)
    if tag.name == "form":
        if prose_rich or (stats.text >= 1200 and stats.link_text * 100 <= 45 * max(1, stats.text)):
            return None
        return "Chrome element"
    if not prose_rich and set(str(tag.get("role", "")).lower().split()) & _CHROME_ROLES:
        return "Chrome role"
    if not prose_rich and _has_chrome_class_or_id(tag):
        return "Chrome class or ID"
    if not prose_rich and tag.name == "header" and not inside_article:
        return "Page header"
    if (
        tag.name in _DENSITY_CONTAINERS and not stats.has_structure
        and 0 < stats.text < 400 and stats.link_text * 100 > 68 * stats.text
    ):
        return "High link density"
    return None


def prune_dom(root: Tag, locations: DomLocations, audit: AuditTrail) -> None:
    metrics = _measure(root)
    total_p_text = sum(metrics[id(child)].p_text for child in root.contents if isinstance(child, Tag))
    pending = [(child, False) for child in reversed(root.contents) if isinstance(child, Tag)]
    while pending:
        tag, inside_article = pending.pop()
        stats = metrics[id(tag)]
        reason = _reason(tag, stats, inside_article, total_p_text)
        if reason:
            audit.operations.append(Operation(
                "PRUNE_BOILERPLATE", locations.path(tag), reason, tokens_saved=stats.tokens,
            ))
            tag.extract()
            continue
        inside_article |= _is_content(tag)
        pending.extend((child, inside_article) for child in reversed(tag.contents) if isinstance(child, Tag))
