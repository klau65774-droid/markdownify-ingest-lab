"""Deterministic local metrics for the ingestion workbench."""

import re

_TOKENS = re.compile(r"[\u4e00-\u9fff]|[A-Za-z0-9]+|[^\sA-Za-z0-9\u4e00-\u9fff]")


def token_estimate(text: str) -> int:
    """Count approximate tokens without an external tokenizer or a network call."""
    return len(_TOKENS.findall(text))


def reduction_rate(before: int, after: int) -> float:
    return (before - after) / before if before else 0.0
