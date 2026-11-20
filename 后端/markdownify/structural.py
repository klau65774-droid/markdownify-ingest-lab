"""Markdown table layout and code-language hints."""

import re
from typing import Callable, Dict, List, Match, Optional, Set, Tuple

from bs4 import Tag

MAX_TABLE_SLOTS = 250_000
_ROW_GROUPS = {"thead", "tbody", "tfoot"}
_CELL_NAMES = ["td", "th"]
_PIPES = re.compile(r"(?<!\\)(\\*)\|")
_DIVIDER = re.compile(r":?-{1,}:?")
_FENCE = re.compile(r"([~]{3,}|`{3,})(.*)")
_CONTAINER_PREFIX = re.compile(r"^(?:>[ \t]*|(?:[-*+]|[0-9]{1,9}[.)])[ \t]+(?=[|>`~]))+")
# Accept only flat, explicitly closed list markup with plain text. Anything
# requiring entity decoding, recovery, or child-tag conversion uses BeautifulSoup.
_OL_START = re.compile(r"""\s*<ol(?:\s+start\s*=\s*(["']?)([0-9]{1,18})\1)?\s*>\s*""", re.ASCII | re.IGNORECASE)
_OL_ITEM = re.compile(r"<li\s*>([^<&]*)</li\s*>\s*", re.ASCII | re.IGNORECASE)
_OL_END = re.compile(r"</ol\s*>\s*\Z", re.ASCII | re.IGNORECASE)
_LANGUAGE = re.compile(r"[A-Za-z0-9_+-]{1,64}")
_LANGUAGE_HINT = re.compile(
    r"(?:^|\s)(?:language-|lang-|highlight-source-|brush:\s*)([a-z0-9_+-]{1,64})(?=$|[\s;])",
    re.IGNORECASE,
)
_LANGUAGE_ALIASES = {
    "py": "python", "js": "javascript", "ts": "typescript",
    "sh": "bash", "zsh": "bash", "yml": "yaml", "c++": "cpp",
}


def infer_language(pre: Tag) -> str:
    for node in (pre, pre.find("code")):
        if node is None:
            continue
        for name in ("data-lang", "data-language", "class"):
            value = node.get(name) or ""
            if isinstance(value, list):
                value = " ".join(value)
            match = _LANGUAGE_HINT.search(value)
            if match:
                language = match[1].lower()
            elif name != "class" and _LANGUAGE.fullmatch(value.strip()):
                language = value.strip().lower()
            else:
                continue
            return _LANGUAGE_ALIASES.get(language, language)
    return ""


def span_width(raw: object, limit: int) -> int:
    if not isinstance(raw, str) or not raw.isdecimal():
        return 1
    width = 0
    for digit in raw:
        width = width * 10 + int(digit)
        if width >= limit:
            return limit
    return max(1, width)


def plain_ordered_items(html: str) -> Optional[Tuple[int, List[str]]]:
    opening = _OL_START.match(html)
    if opening is None:
        return None
    position = opening.end()
    items = []
    while True:
        item = _OL_ITEM.match(html, position)
        if item is None:
            break
        items.append(item[1])
        position = item.end()
    if not items or not _OL_END.match(html, position):
        return None
    return int(opening[2] or 1), items


def escape_table_pipes(text: str) -> str:
    def escape(match: Match[str]) -> str:
        slashes = match[1]
        return match[0] if len(slashes) % 2 else slashes + r"\|"

    return _PIPES.sub(escape, text)


def _rows(table: Tag) -> List[Tag]:
    rows: List[Tag] = []
    for child in table.find_all(["tr", *_ROW_GROUPS], recursive=False):
        if child.name == "tr":
            rows.append(child)
        else:
            rows.extend(child.find_all("tr", recursive=False))
    return rows


def check_slot_budget(slots: int) -> None:
    if slots > MAX_TABLE_SLOTS:
        from .guard import BudgetExceededError

        raise BudgetExceededError("max_nodes", MAX_TABLE_SLOTS, slots)


def _place_cells(rows: List[Tag]) -> Tuple[List[Dict[int, Tag]], int, int]:
    occupied_until: List[int] = []
    anchors: List[Dict[int, Tag]] = []
    cells_expanded = 0
    for row_index, row in enumerate(rows):
        row_anchors: Dict[int, Tag] = {}
        column = 0
        for cell in row.find_all(_CELL_NAMES, recursive=False):
            colspan = span_width(cell.get("colspan"), 32)
            rowspan = min(len(rows) - row_index, span_width(cell.get("rowspan"), 32))
            while True:
                end = column + colspan
                check_slot_budget(len(rows) * end)
                for pending in range(column, min(end, len(occupied_until))):
                    if occupied_until[pending] > row_index:
                        column = pending + 1
                        break
                else:
                    break
            if end > len(occupied_until):
                occupied_until.extend([0] * (end - len(occupied_until)))
            occupied_until[column:end] = [row_index + rowspan] * colspan
            row_anchors[column] = cell
            cells_expanded += colspan * rowspan - 1
            column = end
        anchors.append(row_anchors)
    return anchors, len(occupied_until), cells_expanded


def render_table(
    table: Tag, parent_tags: Set[str], process_element: Callable[..., str],
    *, infer_header: bool, observe: Optional[Callable[[Tag, int, int], None]],
) -> str:
    rows = _rows(table)
    anchors, width, expanded = _place_cells(rows)
    table_context = parent_tags | {"table"}
    extras = "".join(
        process_element(child, parent_tags=table_context)
        for child in table.contents
        if not isinstance(child, Tag) or child.name not in _ROW_GROUPS | {"tr"}
    ).strip()
    if not width:
        return extras
    check_slot_budget((len(rows) + 2) * width)
    if observe is not None:
        observe(table, (len(rows) + 2) * width, expanded)
    output: List[str] = []
    for row_index, row in enumerate(rows):
        context = table_context | {row.parent.name, "tr"} if row.parent is not None else table_context
        values = [""] * width
        for index, cell in anchors[row_index].items():
            value = " ".join(process_element(cell, parent_tags=context).strip().splitlines())
            values[index] = escape_table_pipes(value)
        output.append("| " + " | ".join(values) + " |")
    first_row = rows[0]
    has_heading = (
        infer_header or (first_row.parent is not None and first_row.parent.name == "thead")
        or (bool(anchors[0]) and all(cell.name == "th" for cell in anchors[0].values()))
    )
    if not has_heading:
        output.insert(0, "| " + " | ".join([""] * width) + " |")
    output.insert(1, "| " + " | ".join(["---"] * width) + " |")
    rendered = "\n".join(output)
    return f"{extras}\n\n{rendered}" if extras else rendered


def _row_cells(line: str) -> Tuple[List[str], bool]:
    delimiters = [match.end() - 1 for match in _PIPES.finditer(line) if len(match[1]) % 2 == 0]
    if not delimiters:
        return [], False
    leading = delimiters[0] == 0
    trailing = delimiters[-1] == len(line) - 1
    parts = []
    start = 1 if leading else 0
    for delimiter in delimiters[1 if leading else 0:]:
        parts.append(line[start:delimiter].strip())
        start = delimiter + 1
    if not trailing:
        parts.append(line[start:].strip())
    return parts, leading and trailing


def markdown_table_metrics(markdown: str) -> Tuple[List[int], bool]:
    """Count rendered table cells, excluding escaped pipes and fenced examples."""
    counts: List[int] = []
    aligned = True
    group: List[List[str]] = []
    framed = True
    fence = ""

    def divider(row: List[str]) -> bool:
        return bool(row) and all(_DIVIDER.fullmatch(cell) is not None for cell in row)

    def finish() -> None:
        nonlocal aligned, framed
        if group and ((framed and len(group) > 1) or any(divider(row) for row in group)):
            widths = [len(row) for row in group]
            counts.extend(widths)
            aligned &= len(group) >= 2 and divider(group[1]) and len(set(widths)) == 1
        group.clear()
        framed = True

    for raw_line in markdown.splitlines():
        line = raw_line.strip()
        # List markers and blockquotes can be nested around a table or fence.
        line = _CONTAINER_PREFIX.sub("", line, count=1)
        delimiter = _FENCE.fullmatch(line)
        if fence:
            if delimiter and delimiter[1].startswith(fence) and not delimiter[2].strip():
                fence = ""
            continue
        if delimiter:
            finish()
            fence = delimiter[1]
        else:
            row, bordered = _row_cells(line)
            if row or bordered:
                group.append(row)
                framed &= bordered
            else:
                finish()
    finish()
    return counts, aligned
