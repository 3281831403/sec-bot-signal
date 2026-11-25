"""Bot-signal scoring package."""

from .api import (
    bot_batch,
    decide,
    dedupe,
    parse_signals,
    resolve_conflict,
    score,
    validate_policy,
    weight_of,
)

__all__ = [
    "parse_signals",
    "weight_of",
    "resolve_conflict",
    "score",
    "decide",
    "dedupe",
    "validate_policy",
    "bot_batch",
]