"""Bound HTML input and sanitize credentials and resource destinations."""

import re
from html import unescape
from html.parser import HTMLParser
from typing import Literal
from urllib.parse import unquote, unquote_plus, urlsplit

from bs4 import BeautifulSoup, ParserRejectedMarkup, Tag
from bs4.builder import HTMLTreeBuilder

from .audit import Action, AuditTrail, DomLocations, Operation, OutputProbe

MAX_BYTES = 524_288
MAX_DEPTH = 96
MAX_NODES = 25_000
BudgetCode = Literal["max_bytes", "max_depth", "max_nodes"]


class BudgetExceededError(ValueError):
    def __init__(self, code: BudgetCode, limit: int, observed: int) -> None:
        self.code = code
        self.limit = limit
        self.observed = observed
        super().__init__(f"{code}: limit {limit}, observed {observed}")


class HTMLInputError(ValueError):
    """The selected parser or baseline cannot convert the supplied markup."""


VOID_TAGS = frozenset(HTMLTreeBuilder.DEFAULT_EMPTY_ELEMENT_TAGS or ())


class _BudgetParser(HTMLParser):
    def __init__(self, max_depth: int, max_nodes: int) -> None:
        # Text has no bearing on depth or tag count. Let the DOM parser decode it.
        super().__init__(convert_charrefs=False)
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.nodes = 0
        self.stack: list[str] = []
        self.open_tags: dict[str, list[int]] = {}

    def _count_tag(self) -> None:
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise BudgetExceededError("max_nodes", self.max_nodes, self.nodes)
        depth = len(self.stack) + 1
        if depth > self.max_depth:
            raise BudgetExceededError("max_depth", self.max_depth, depth)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._count_tag()
        if tag not in VOID_TAGS:
            self.open_tags.setdefault(tag, []).append(len(self.stack))
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._count_tag()

    def handle_endtag(self, tag: str) -> None:
        positions = self.open_tags.get(tag)
        if positions:
            for _ in range(len(self.stack) - positions[-1]):
                self.open_tags[self.stack.pop()].pop()


def utf8_size(text: str) -> int:
    if text.isascii():
        return len(text)
    if len(text) <= MAX_BYTES:
        return len(text.encode("utf-8"))
    # Preserve the exact observed size without a second document-sized allocation.
    chunk = 65_536
    return sum(len(text[i:i + chunk].encode("utf-8")) for i in range(0, len(text), chunk))


def validate_html_budget(
    raw_html: str, *, max_bytes: int = MAX_BYTES,
    max_depth: int = MAX_DEPTH, max_nodes: int = MAX_NODES,
) -> None:
    """Reject over-budget input before allocating or recursively walking a DOM."""
    size = utf8_size(raw_html)
    if size > max_bytes:
        raise BudgetExceededError("max_bytes", max_bytes, size)
    parser = _BudgetParser(max_depth, max_nodes)
    try:
        parser.feed(raw_html)
        parser.close()
    except BudgetExceededError:
        raise
    except (AssertionError, ValueError) as exc:
        raise HTMLInputError("HTML parser rejected the input") from exc


def parse_html(raw_html: str) -> BeautifulSoup:
    validate_html_budget(raw_html)
    try:
        return BeautifulSoup(raw_html, "html.parser")
    except (ParserRejectedMarkup, ValueError, OverflowError) as exc:
        raise HTMLInputError("HTML parser rejected the input") from exc


# Escaped underscores also occur in upstream Markdown previews.
_UNDERSCORE = r"\\?_"
_TOKEN_CHAR = r"(?:[A-Za-z0-9-]|\\?_)"
_SECRET = re.compile(
    r"(?<![A-Za-z0-9_+])(?:"
    r"(?P<aws>AKIA[A-Z0-9]{16})"
    r"|(?P<aliyun>LTAI[A-Za-z0-9]{12,32})"
    rf"|(?P<github>gh[pousr]{_UNDERSCORE}[A-Za-z0-9]{{16,}})"
    rf"|(?P<github_pat>github{_UNDERSCORE}pat{_UNDERSCORE}(?:[A-Za-z0-9]|{_UNDERSCORE}){{20,}})"
    rf"|(?P<anthropic>sk-ant-{_TOKEN_CHAR}{{16,}})"
    rf"|(?P<openai>sk-{_TOKEN_CHAR}{{16,}})"
    rf"|(?P<stripe_key>sk{_UNDERSCORE}(?:live|test){_UNDERSCORE}[A-Za-z0-9]{{16,}})"
    rf"|(?P<stripe_restricted>rk{_UNDERSCORE}(?:live|test){_UNDERSCORE}[A-Za-z0-9]{{16,}})"
    r"|(?P<slack>xox[baprs]-[A-Za-z0-9-]{16,})"
    rf"|(?P<google>AIza{_TOKEN_CHAR}{{35}})"
    rf"|(?P<huggingface>hf{_UNDERSCORE}[A-Za-z0-9]{{20,}})"
    rf"|(?P<bearer>(?i:bearer)[ \t]+(?:[A-Za-z0-9.~+/\-=]|{_UNDERSCORE})+)"
    rf"|(?P<jwt>eyJ{_TOKEN_CHAR}{{4,}}\.{_TOKEN_CHAR}+\.{_TOKEN_CHAR}+)"
    r"|(?P<dsn>(?i:postgres(?:ql)?|mysql|rediss?)://"
    r"""[^:/@"'\s]+:[^/"'\s]+@)"""
    r"|(?P<mobile>(?:\+?86[ \t-]?)?1[3-9][0-9]{9})(?![A-Za-z0-9_+-])"
    r")(?(dsn)|(?![A-Za-z0-9_]))"
)
_URL_TEXT = re.compile(r"""(?i)\bhttps?://[^\s<>"']+""")
_PHONE_PARAMETER = re.compile(r"(?:[?&](?:phone|mobile|tel)=|tel:)\+?$", re.IGNORECASE)
_AUTH_HEADER = re.compile(r"\bauthorization[ \t]*:[ \t]*$", re.IGNORECASE)
_BEARER_TERMS = frozenset({
    "auth", "authentication", "authorization", "bond", "bonds", "credential", "credentials",
    "of", "scheme", "token", "tokens",
})


def _is_bearer_credential(text: str, match: re.Match[str]) -> bool:
    start, end = match.span()
    while start and text[start - 1] in " \t":
        start -= 1
    if _AUTH_HEADER.search(text, max(0, start - 64), start):
        return True

    value = match[0].split(None, 1)[1].rstrip(".")
    if not value or value.casefold() in _BEARER_TERMS:
        return False
    if any(char in "_~+=" for char in value) or (
        any(char.isdigit() for char in value) and any(char.isalpha() for char in value)
    ):
        return True
    if _SECRET.fullmatch(value):
        return True

    # Short alphabetic values are common in fixtures. Require a standalone
    # credential or an explicit Authorization header when the value is ambiguous.
    if start and text[start - 1] not in "\r\n":
        return False
    while end < len(text) and text[end] in " \t":
        end += 1
    return end == len(text) or text[end] in "\r\n"


def redact_secrets(text: str) -> tuple[str, int]:
    """Replace credential occurrences and return the masked text and count."""
    count = 0
    # A phone-shaped number in a URL can be an ordinary resource ID.
    urls = iter(_URL_TEXT.finditer(text))
    url = next(urls, None)

    def replace(match: re.Match[str]) -> str:
        nonlocal count, url
        if match.lastgroup == "bearer" and not _is_bearer_credential(text, match):
            return match[0]
        if match.lastgroup == "mobile":
            while url is not None and url.end() <= match.start():
                url = next(urls, None)
            if (
                url is not None and url.start() <= match.start()
                and not _PHONE_PARAMETER.search(text[max(url.start(), match.start() - 10):match.start()])
            ):
                return match[0]
        count += 1
        if match.lastgroup == "dsn":
            return match[0].partition("://")[0] + "://[REDACTED]@"
        return "[REDACTED]"

    return _SECRET.sub(replace, text), count


TRACKING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "mc_cid", "mc_eid", "spm", "_hsenc", "_hsmi", "igshid",
    "mkt_tok", "yclid", "msclkid",
})
_SCHEME_NOISE = re.compile(r"[\s\x00-\x1f\x7f]+")
_BEACON_PATH = re.compile(r"(?:^|/)(?:tracking[-_]?pixel|pixel|beacon|track)(?:\.(?:gif|png))?$", re.IGNORECASE)
_WEBHOOK_PATH = re.compile(r"(?:^|/)(?:webhook|webhooks)(?:/|$)", re.IGNORECASE)
_WEBHOOK_HOSTS = frozenset({"webhook.site", "requestbin.com", "pipedream.net"})
_WEBHOOK_VARIABLE = re.compile(
    r"(?:\$\{|\{\{)[^{}]{0,64}(?:key|secret|token|password|credential|prompt|conversation)"
    r"[^{}]{0,64}\}", re.IGNORECASE,
)
_DESTINATION_END = re.compile(r"""[\x00-\x20<>"\\]""")
INVISIBLE_CONTROLS = re.compile(
    "[\u200b-\u200f\u2060-\u2064\ufeff\u00ad\u034f\u180e\u202a-\u202e"
    "\u2066-\u2069\U000e0000-\U000e007f]"
)


def strip_invisible(text: str) -> str:
    return INVISIBLE_CONTROLS.sub("", text)


def unsafe_uri_scheme(uri: str) -> str | None:
    # Check only the scheme and media type. The path does not affect the decision.
    prefix, colon, suffix = unquote(unescape(uri)).partition(":")
    if not colon:
        return None
    scheme = _SCHEME_NOISE.sub("", prefix).lower()
    if scheme in {"javascript", "vbscript", "file"}:
        return scheme
    if scheme == "data":
        media_type = _SCHEME_NOISE.sub("", re.split(r"[;,]", suffix, maxsplit=1)[0]).lower()
        if media_type == "text/html" or media_type.startswith("application/"):
            return "data:" + ("text/html" if media_type == "text/html" else "application/")
    return None


def clean_tracking_url(uri: str) -> tuple[str, int]:
    try:
        parsed = urlsplit(uri)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or not parsed.query:
            return uri, 0
    except ValueError:
        return uri, 0
    before_fragment, fragment_sep, fragment = uri.partition("#")
    base, _, raw_query = before_fragment.partition("?")
    params = raw_query.split("&")
    kept = [param for param in params if unquote_plus(param.partition("=")[0]).lower() not in TRACKING_PARAMS]
    removed = len(params) - len(kept)
    if not removed:
        return uri, 0
    query = "?" + "&".join(kept) if kept else ""
    return base + query + fragment_sep + fragment, removed


def is_webhook_destination(uri: str) -> bool:
    """Recognize image destinations that reference sensitive template variables."""
    try:
        url = urlsplit(unquote(uri))
        if url.scheme not in {"", "http", "https"} or not url.hostname:
            return False
    except ValueError:
        return False
    host = url.hostname.rstrip(".")
    return bool(
        _WEBHOOK_VARIABLE.search(url.query) or _WEBHOOK_PATH.search(url.path)
        or any(host == domain or host.endswith("." + domain) for domain in _WEBHOOK_HOSTS)
    )


def inline_style(style: str) -> dict[str, str]:
    """Read relevant declarations with CSS comment and priority handling."""
    style = re.sub(r"/\*.*?(?:\*/|\Z)", "", style, flags=re.DOTALL)
    declarations: dict[str, str] = {}
    important: set[str] = set()
    for declaration in style.split(";"):
        name, sep, value = declaration.partition(":")
        if not sep:
            continue
        name, value = name.strip().lower(), value.strip().lower()
        value, priority = re.subn(r"!\s*important$", "", value)
        if priority or name not in important:
            declarations[name] = value.rstrip()
        if priority:
            important.add(name)
    return declarations


def _tracking_pixel(image: Tag, uri: str) -> bool:
    style = inline_style(str(image.get("style", "")))
    width = style.get("width", str(image.get("width", ""))).strip()
    height = style.get("height", str(image.get("height", ""))).strip()
    single = {"1", "1px"}
    if (width in single and (not height or height in single)) or (not width and height in single):
        return True
    try:
        url = urlsplit(uri)
        return bool(
            _BEACON_PATH.search(url.path)
            or (url.hostname == "pixel.wp.com" and url.path == "/g.gif")
            or (url.hostname == "www.facebook.com" and url.path.rstrip("/") == "/tr")
        )
    except ValueError:
        return False


def _destination_attributes(node: Tag) -> tuple[str, ...]:
    if node.name == "a":
        return ("href",)
    if node.name == "video":
        return ("src", "poster")
    if node.name == "img" or (node.name == "source" and node.find_parent("video")):
        return ("src",)
    return ()


def _markdown_destination(uri: str) -> str:
    # Keep whitespace and unbalanced delimiters inside the same destination.
    uri = _DESTINATION_END.sub(lambda match: f"%{ord(match[0]):02X}", uri)
    if uri.count("(") != uri.count(")") or ")" in uri.partition("(")[0]:
        return uri.replace("(", "%28").replace(")", "%29")
    depth = 0
    for delimiter in re.finditer(r"[()]", uri):
        depth += 1 if delimiter[0] == "(" else -1
        if depth < 0:
            return uri.replace("(", "%28").replace(")", "%29")
    return uri


def sanitize_url_attributes(
    node: Tag, locations: DomLocations, audit: AuditTrail, *,
    enabled: bool, hidden_removed: bool, upstream_scope: Tag | None,
) -> None:
    for attr in _destination_attributes(node):
        uri = node.get(attr)
        if not isinstance(uri, str):
            uri = ""
        if not uri and node.name != "img":
            continue
        uri = strip_invisible(uri)
        unsafe = unsafe_uri_scheme(uri)
        webhook = (node.name == "img" or attr == "poster") and is_webhook_destination(uri)
        if unsafe or webhook:
            path = f"{locations.path(node)}/@{attr}"
            key = f"uri:{unsafe}" if unsafe else "uri:webhook"
            action: Action = "flagged"
            if hidden_removed or (enabled and node.name == "img"):
                action = "stripped"
            elif enabled:
                action = "sanitized"
            audit.finding(
                "exfiltration_uri", "high", path,
                f"Blocked scheme {unsafe}" if unsafe else "Image webhook destination",
                action, source=node,
                probe=OutputProbe(node, upstream_scope, key, attr) if upstream_scope is not None else None,
            )
            if enabled:
                audit.operations.append(Operation("STRIP_DANGEROUS_URI", path, key))
                if node.name == "img":
                    if not hidden_removed:
                        node.extract()
                    return
                del node[attr]
        elif enabled and not hidden_removed:
            if node.name == "img" and _tracking_pixel(node, uri):
                audit.operations.append(Operation("STRIP_TRACKING_PIXEL", locations.path(node), "Image beacon"))
                node.extract()
                return
            if not uri:
                continue
            cleaned, removed = clean_tracking_url(uri)
            node[attr] = _markdown_destination(cleaned)
            if removed:
                audit.operations.append(Operation(
                    "CLEAN_TRACKING_URL", f"{locations.path(node)}/@{attr}", "Query parameters", removed,
                ))


def sanitize_urls(root: Tag, locations: DomLocations, audit: AuditTrail, *, enabled: bool) -> None:
    """Sanitize destinations independently of the full ingestion pipeline."""
    for node in root.find_all(["a", "img", "video", "source"]):
        sanitize_url_attributes(node, locations, audit, enabled=enabled, hidden_removed=False, upstream_scope=node)
