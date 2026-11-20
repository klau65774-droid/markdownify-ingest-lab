"""Find indirect instructions in DOM locations that ordinary readers may miss."""

import re
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass
from itertools import accumulate

from bs4 import Comment, Doctype, NavigableString, Tag

from .audit import (
    Action,
    AuditTrail,
    DomLocations,
    Operation,
    OperationKind,
    OutputProbe,
    Severity,
    ThreatCategory,
)
from .guard import (
    INVISIBLE_CONTROLS,
    inline_style,
    is_webhook_destination,
    redact_secrets,
    sanitize_url_attributes,
    strip_invisible,
    unsafe_uri_scheme,
)

_SIGNATURE = re.compile(
    r"(?P<override>\b(?:ignore\s+(?:(?:all|any|the)\s+)?"
    r"(?:previous|prior|above|earlier|preceding)\s+"
    r"(?:instructions|prompts|rules|directions|guidelines)\b"
    r"|disregard\s+(?:all\s+)?(?:previous|prior|above)\b"
    r"|forget\s+(?:everything|all\s+previous|your\s+instructions)\b)"
    r"|忽略(?:(?:之前|以上|所有|前面)){1,3}的?(?:指令|提示|规则|设定))"
    r"|(?P<role><\|(?:im_start|system)\|>|\[SYSTEM\]|"
    r"\#{3}\s*(?:system|instruction)\s*:|\bsystem\s+prompt\s+override\b"
    r"|\byou\s+are\s+now\s+in\s+developer\s+mode\b"
    r"|\bact\s+as\s+an?\s+unrestricted\b|作为系统管理员|进入开发者模式)"
    r"|(?P<exfiltration>\b(?:exfiltrate|steal|leak|transmit|post|send)\s+(?:the\s+)?"
    r"(?:api[_\s-]?key|secret|token|password|credentials|conversation|system\s+prompt|env)\b"
    r"|泄露[^。\uff01\uff1f\n]{0,120}?(?:密钥|密码|系统提示词))",
    re.IGNORECASE,
)
_MARKDOWN_IMAGE = re.compile(r"!\[[^\[\]\n]*\]\((?P<uri>[^\s)]+)")
_MARKDOWN_DESTINATION = re.compile(r"\]\((?P<link>[^\s)]+)|<(?P<autolink>[^<>\s]+)>")
_MARKDOWN_STYLES = re.compile(r"(?<!\\)(?:\*+|~~|\x60+)")
_DIRECTIVE_LEAD = re.compile(r"[^\S\r\n]*(?:(?:[-*+]|\d{1,9}[.)])\s+)?(?:please\s+)?", re.IGNORECASE)
_LINE_BREAK = re.compile(r"\r\n|[\r\n]")
_HIDDEN_TAGS = frozenset({
    "template", "noscript", "iframe", "frame", "object", "embed", "applet",
    "meta", "link", "script", "style", "head",
})
_TEXT_ATTRIBUTES = frozenset({"alt", "title", "aria-label", "placeholder"})
_BLOCKS = frozenset({
    "article", "aside", "blockquote", "div", "dd", "dt", "footer", "form",
    "h1", "h2", "h3", "h4", "h5", "h6", "header", "li", "main", "nav",
    "p", "pre", "section", "td", "th",
})
_EXAMPLE_TAGS = frozenset({"pre", "code", "kbd", "samp", "blockquote", "q"})
_ZERO = r"(?:0+(?:\.0+)?|\.0+)"
_COLOR_ALIASES = {"white": "#ffffff", "black": "#000000"}


def _color(value: str) -> str:
    if re.fullmatch(r"#[0-9a-f]{3}", value):
        return "#" + "".join(char * 2 for char in value[1:])
    return _COLOR_ALIASES.get(value, value)


def _hidden_style(value: str) -> str | None:
    css = inline_style(value)
    color = _color(css.get("color", ""))
    background = _color(css.get("background-color", css.get("background", "")))
    if css.get("display") == "none":
        return "display"
    if css.get("visibility") == "hidden":
        return "visibility"
    if re.fullmatch(_ZERO + "%?", css.get("opacity", "")):
        return "opacity"
    if re.fullmatch(_ZERO + r"(?:px|r?em|pt|%)?", css.get("font-size", "")):
        return "font-size"
    if color == "transparent" or re.fullmatch(r"rgba\([^)]*,\s*" + _ZERO + r"%?\s*\)", color):
        return "color"
    if (
        color == background and color not in {"inherit", "initial", "unset", "revert", "currentcolor"}
        and re.fullmatch(r"#[0-9a-f]{6}|[a-z]+|rgba?\([^)]*\)", color)
    ):
        return "foreground matches background"
    if any(re.fullmatch(r"-\d{3,}px", css.get(prop, "")) for prop in ("text-indent", "left", "top")):
        return "off-screen positioning"
    clip = re.fullmatch(r"rect\(([^()]*)\)", css.get("clip", ""))
    if clip:
        edges = re.split(r"[\s,]+", clip[1].strip())
        if len(edges) == 4:
            zero = [bool(re.fullmatch(_ZERO + "(?:px)?", edge)) for edge in edges]
            if (zero[0] and zero[2]) or (zero[1] and zero[3]):
                return "clip"
    if re.match(r"inset\(\s*100%(?:\s|\))", css.get("clip-path", "")):
        return "clip-path"
    if css.get("overflow") == "hidden" and any(
        re.fullmatch(_ZERO + "(?:px)?", css.get(prop, ""))
        for prop in ("width", "height", "max-width", "max-height")
    ):
        return "zero size with hidden overflow"
    return None


@dataclass(frozen=True, slots=True)
class _Context:
    block: Tag
    in_body: bool = False
    hidden: bool = False
    example: bool = False
    upstream_suppressed: bool = False


@dataclass(frozen=True, slots=True)
class _Match:
    start: int
    end: int
    text: str
    probe: str
    severity: Severity
    image: bool = False


def _matches(text: str) -> list[_Match]:
    matches = [
        _Match(
            match.start(), match.end(), match[0],
            "text:" + " ".join(match[0].casefold().split()),
            "critical" if match.lastgroup == "exfiltration" else "high",
        )
        for match in _SIGNATURE.finditer(text)
    ]
    for match in _MARKDOWN_IMAGE.finditer(text):
        if is_webhook_destination(match["uri"]):
            matches.append(_Match(match.start(), match.end(), match[0], "uri:webhook", "critical", image=True))
    matches.sort(key=lambda found: found.start)
    return matches


def _report(
    audit: AuditTrail, found: _Match, category: ThreatCategory,
    path: str, action: Action, *, source: NavigableString | Tag, probe: OutputProbe | None = None,
) -> None:
    snippet = "Image webhook destination" if found.image else redact_secrets(found.text)[0]
    audit.finding(
        "exfiltration_uri" if found.image else category, found.severity,
        redact_secrets(path)[0], snippet[:160], action, source=source, probe=probe,
    )


def _without_invisible(
    text: str, path: str, audit: AuditTrail, *, apply: bool,
) -> str:
    cleaned, count = INVISIBLE_CONTROLS.subn("", text)
    if count and apply:
        audit.operations.append(Operation("STRIP_ZERO_WIDTH", path, "Unicode controls", count))
    return cleaned


def _inspect_attributes(
    node: Tag, locations: DomLocations, audit: AuditTrail, *, apply: bool, removed: bool,
    upstream_suppressed: bool,
) -> None:
    for name, value in list(node.attrs.items()):
        if not isinstance(value, (str, list)) or not value:
            continue
        suspicious = name in _TEXT_ATTRIBUTES or name.startswith("data-")
        if not suspicious and not INVISIBLE_CONTROLS.search(str(value)):
            continue
        path = f"{locations.path(node)}/@{redact_secrets(name)[0][:64]}"
        raw = value if isinstance(value, str) else " ".join(value)
        cleaned = _without_invisible(raw, path, audit, apply=apply)
        if suspicious and (matches := _matches(cleaned)):
            emitted = not upstream_suppressed and (
                (node.name == "img" and name == "alt") or (node.name in {"a", "img"} and name == "title")
            )
            action: Action = "stripped" if removed else "sanitized" if apply else "flagged"
            for found in matches:
                probe = OutputProbe(node, node, found.probe, name, found.start) if emitted else None
                _report(audit, found, "attribute_injection", path, action, source=node, probe=probe)
            if apply and not removed:
                del node[name]
                audit.operations.append(Operation("STRIP_SUSPICIOUS_ATTRIBUTE", path, "Indirect instruction"))
        elif apply and not removed and cleaned != raw:
            node[name] = cleaned if isinstance(value, str) else type(value)(cleaned.split())


def _line_edits(
    removed_lines: list[tuple[int, int]], breaks: list[re.Match[str]], text_length: int,
) -> list[tuple[int, int]]:
    edits = []
    for first, last in removed_lines:
        if last < len(breaks):
            start = breaks[first - 1].end() if first else 0
            edits.append((start, breaks[last].end()))
        else:
            start = breaks[first - 1].start() if first else 0
            edits.append((start, text_length))
    return edits


def _apply_run_edits(
    nodes: list[NavigableString | Tag], fragments: list[str],
    edits: list[tuple[int, int]], locations: DomLocations, audit: AuditTrail,
) -> None:
    offset = edit_index = 0
    for node, fragment in zip(nodes, fragments, strict=True):
        original = "\n" if isinstance(node, Tag) else str(node)
        count = len(original) - len(fragment)
        if count:
            audit.operations.append(Operation("STRIP_ZERO_WIDTH", locations.path(node), "Unicode controls", count))

        end = offset + len(fragment)
        kept = []
        cursor = offset
        while edit_index < len(edits):
            edit_start, edit_end = edits[edit_index]
            if edit_start >= end:
                break
            if cursor < edit_start:
                kept.append(fragment[cursor - offset:edit_start - offset])
            cursor = min(end, edit_end)
            if edit_end > end:
                break
            edit_index += 1
        kept.append(fragment[cursor - offset:])
        offset = end
        replacement = "".join(kept)
        if replacement == original:
            continue
        if not replacement:
            node.extract()
        elif isinstance(node, NavigableString):
            updated = type(node)(replacement)
            locations.relocate(node, updated)
            node.replace_with(updated)


def _inspect_run(
    nodes: list[NavigableString | Tag], context: _Context, locations: DomLocations, audit: AuditTrail,
    *, strict: bool, apply: bool, strip_hidden: bool,
) -> None:
    if not nodes:
        return
    fragments = ["\n" if isinstance(node, Tag) else str(node) for node in nodes]
    raw = "".join(fragments)
    controls = [match.start() - index for index, match in enumerate(INVISIBLE_CONTROLS.finditer(raw))]
    if controls:
        fragments = [strip_invisible(fragment) for fragment in fragments]
    cleaned = "".join(fragments) if controls else raw
    matches = _matches(cleaned) if context.hidden or (not context.example and (strict or controls)) else []
    breaks = list(_LINE_BREAK.finditer(cleaned)) if matches and not context.hidden else []
    line_starts = [0, *(match.end() for match in breaks)]
    fragment_ends = list(accumulate(map(len, fragments))) if matches else []
    removed_lines: list[tuple[int, int]] = []

    for found in matches:
        fragment_index = bisect_right(fragment_ends, found.start)
        fragment_start = fragment_ends[fragment_index - 1] if fragment_index else 0
        source = nodes[fragment_index]
        probe = None if context.upstream_suppressed else OutputProbe(
            source, context.block, found.probe, offset=found.start - fragment_start,
        )
        if context.hidden:
            _report(
                audit, found, "hidden_dom", locations.path(source),
                "stripped" if strip_hidden and apply else "flagged", source=source, probe=probe,
            )
            continue
        first_line = bisect_right(line_starts, found.start) - 1
        line_start = line_starts[first_line]
        leading = found.start - line_start <= 64 and bool(
            _DIRECTIVE_LEAD.fullmatch(cleaned, line_start, found.start)
        )
        obfuscated = bisect_right(controls, found.start) < bisect_right(controls, found.end - 1)
        if not (obfuscated or found.image or (strict and leading)):
            continue
        stripped = apply and strict
        category: ThreatCategory = "zero_width" if obfuscated else "instruction_override"
        _report(
            audit, found, category, locations.path(source), "stripped" if stripped else "flagged",
            source=source, probe=probe,
        )
        if stripped:
            last_line = bisect_right(line_starts, found.end - 1) - 1
            if removed_lines and first_line <= removed_lines[-1][1] + 1:
                previous_start, previous_end = removed_lines[-1]
                removed_lines[-1] = previous_start, max(previous_end, last_line)
            else:
                removed_lines.append((first_line, last_line))

    if not apply:
        return
    if removed_lines:
        audit.operations.append(Operation(
            "STRIP_INSTRUCTION", locations.path(context.block), "Visible indirect instruction",
            count=sum(last - first + 1 for first, last in removed_lines),
        ))
    if controls or removed_lines:
        edits = _line_edits(removed_lines, breaks, len(cleaned))
        _apply_run_edits(nodes, fragments, edits, locations, audit)


def guard_dom(
    root: Tag, locations: DomLocations, audit: AuditTrail,
    *, strip_hidden: bool, strict: bool, apply: bool, clean_urls: bool = True,
) -> None:
    contexts = {id(root): _Context(root)}
    video_sources: dict[int, Tag | None] = {}
    hidden_nodes: list[Tag] = []
    comments: list[Comment] = []
    # Process hidden text independently so removing a hidden inline node cannot
    # join two visible fragments into a directive the scanner has never seen.
    runs: dict[bool, tuple[_Context, list[NavigableString | Tag]]] = {
        False: (contexts[id(root)], []),
        True: (contexts[id(root)], []),
    }
    for node in list(root.descendants):
        parent = contexts.get(id(node.parent), contexts[id(root)])
        if isinstance(node, Tag):
            hidden_attr = (
                node.name in _HIDDEN_TAGS or (node.name == "title" and not parent.in_body)
                or node.has_attr("hidden") or strip_invisible(str(node.get("aria-hidden", ""))).strip().lower() == "true"
            )
            style = str(node.get("style", ""))
            hidden_style = _hidden_style(strip_invisible(style)) if style else None
            hidden = parent.hidden or hidden_attr or bool(hidden_style)
            if apply and strip_hidden and hidden and not parent.hidden:
                hidden_nodes.append(node)
                kind: OperationKind = "STRIP_HIDDEN_ATTR" if hidden_attr else "STRIP_HIDDEN_STYLE"
                audit.operations.append(Operation(kind, locations.path(node), hidden_style or "Hidden DOM"))
            contexts[id(node)] = _Context(
                node if node.name in _BLOCKS or (hidden and not parent.hidden) else parent.block,
                parent.in_body or node.name == "body", hidden,
                parent.example or node.name in _EXAMPLE_TAGS,
                parent.upstream_suppressed or node.name in {"script", "style"},
            )
            _inspect_attributes(
                node, locations, audit, apply=apply, removed=apply and strip_hidden and hidden,
                upstream_suppressed=contexts[id(node)].upstream_suppressed,
            )
            if node.name in {"a", "img", "video", "source"}:
                upstream_scope: Tag | None = node
                if contexts[id(node)].upstream_suppressed:
                    upstream_scope = None
                elif node.name == "source":
                    video = node.find_parent("video")
                    upstream_scope = None
                    if isinstance(video, Tag):
                        if id(video) not in video_sources:
                            video_sources[id(video)] = None if video.get("src") else video.find("source", src=True)
                        if video_sources[id(video)] is node:
                            upstream_scope = video
                sanitize_url_attributes(
                    node, locations, audit, enabled=clean_urls and apply,
                    hidden_removed=apply and strip_hidden and hidden,
                    upstream_scope=upstream_scope,
                )
            if node.name != "br":
                continue
            parent = contexts[id(node)]
        elif isinstance(node, Comment):
            path = locations.path(node)
            cleaned = _without_invisible(str(node), path, audit, apply=apply)
            for found in _matches(cleaned):
                _report(
                    audit, found, "comment_injection", path,
                    "stripped" if apply and strip_hidden else "flagged", source=node,
                )
            if apply and strip_hidden:
                comments.append(node)
                audit.operations.append(Operation("STRIP_HIDDEN_ATTR", path, "HTML comment"))
            continue
        elif not isinstance(node, NavigableString) or isinstance(node, Doctype):
            continue
        run_context, run = runs[parent.hidden]
        if (
            parent.block is not run_context.block or parent.example != run_context.example
            or parent.upstream_suppressed != run_context.upstream_suppressed
        ):
            _inspect_run(run, run_context, locations, audit, strict=strict, apply=apply, strip_hidden=strip_hidden)
            run = []
            runs[parent.hidden] = (parent, run)
        run.append(node)
    for run_context, run in runs.values():
        _inspect_run(run, run_context, locations, audit, strict=strict, apply=apply, strip_hidden=strip_hidden)
    for node in comments:
        node.extract()
    for hidden_node in hidden_nodes:
        hidden_node.extract()


def rendered_probes(markdown: str) -> Counter[str]:
    cleaned = strip_invisible(markdown).replace(r"\_", "_")
    probes = Counter(found.probe for found in _matches(_MARKDOWN_STYLES.sub("", cleaned)))
    for match in _MARKDOWN_DESTINATION.finditer(cleaned):
        uri = match["link"] or match["autolink"]
        if unsafe := unsafe_uri_scheme(uri):
            probes[f"uri:{unsafe}"] += 1
    return probes
