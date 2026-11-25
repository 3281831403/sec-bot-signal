"""Bot-signal scoring core.

The public API accepts plain Python mappings so callers can pass decoded
request telemetry without constructing library-specific objects.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from typing import Any

_ALLOW = "allow"
_CHALLENGE = "challenge"
_BLOCK = "block"

_VERDICTS = {_ALLOW, _CHALLENGE, _BLOCK}
_VERDICT_ALIASES = {
    "allow": _ALLOW,
    "pass": _ALLOW,
    "permit": _ALLOW,
    "challenge": _CHALLENGE,
    "verify": _CHALLENGE,
    "block": _BLOCK,
    "deny": _BLOCK,
    "ban": _BLOCK,
}

_AUTOMATION_MARKERS = frozenset(
    {
        "automation",
        "webdriver",
        "headless",
        "cdp",
        "devtools",
        "selenium",
        "puppeteer",
        "playwright",
        "phantom",
    }
)

_TRUTHY = {"1", "true", "yes", "y", "on"}
_FALSY = {"0", "false", "no", "n", "off", ""}


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _number(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        result = float(value)
        return result if math.isfinite(result) else default
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _TRUTHY:
            return 1.0
        if text in _FALSY:
            return 0.0
        try:
            result = float(text)
        except ValueError:
            return default
        return result if math.isfinite(result) else default
    return default


def _clamp(value: float, low: float, high: float) -> float:
    if low > high:
        low, high = high, low
    return max(low, min(high, value))


def _verdict(value: Any) -> str | None:
    return _VERDICT_ALIASES.get(_text(value))


def _looks_like_signal(value: Any) -> bool:
    return isinstance(value, Mapping) and "name" in value


def _parse_text_signal(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if not text:
        return None

    source = "unknown"
    pieces = text.split(":", 2)
    if len(pieces) == 3:
        source, name_part, verdict_part = pieces
        verdict = _verdict(verdict_part)
    elif len(pieces) == 2:
        source, name_part = pieces
        verdict = None
    else:
        name_part = pieces[0]
        verdict = None

    if "=" in name_part:
        name, raw_value = name_part.split("=", 1)
    else:
        name, raw_value = name_part, "1"

    name = _text(name)
    if not name:
        return None

    return {
        "name": name,
        "value": _number(raw_value, 1.0),
        "source": _text(source) or "unknown",
        "verdict": verdict,
    }


def _automation_signal(name: str, source: str, item: Mapping[str, Any]) -> bool:
    if item.get("automation") is True:
        return True
    if source == "automation":
        return True
    if name in _AUTOMATION_MARKERS:
        return True
    return any(marker in name for marker in _AUTOMATION_MARKERS)


def parse_signals(raw: Any) -> list[dict[str, Any]]:
    """Normalize raw signal input into dictionaries.

    A signal has a name, a numeric value, a source, a verdict and a
    confidence. Text entries use source:name=value with an optional verdict.
    """

    if raw is None:
        return []
    if _looks_like_signal(raw):
        items: Iterable[Any] = [raw]
    elif isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, Mapping):
        items = list(raw.values())
    else:
        try:
            items = list(raw)
        except TypeError:
            items = [raw]

    parsed: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, Mapping):
            name = _text(item.get("name"))
            if not name:
                continue
            source = _text(item.get("source")) or "unknown"
            value = _number(item.get("value"), 0.0)
            verdict = _verdict(item.get("verdict"))
            confidence = _clamp(_number(item.get("confidence"), 1.0), 0.0, 1.0)
            automation = _automation_signal(name, source, item)
            if verdict is None:
                if automation:
                    verdict = _BLOCK
                elif value > 0:
                    verdict = _CHALLENGE
                else:
                    verdict = _ALLOW
            neutral = automation
            record: dict[str, Any] = {
                "name": name,
                "value": value,
                "source": source,
                "verdict": verdict,
                "confidence": confidence,
                "automation": automation,
                "neutral": neutral,
            }
            if "session" in item:
                record["session"] = str(item.get("session"))
            parsed.append(record)
            continue

        if isinstance(item, str):
            record = _parse_text_signal(item)
            if record is None:
                continue
            name = record["name"]
            source = record["source"]
            automation = _automation_signal(name, source, record)
            record["confidence"] = 1.0
            record["automation"] = automation
            record["neutral"] = automation
            if record.get("verdict") is None:
                if automation:
                    record["verdict"] = _BLOCK
                elif record["value"] > 0:
                    record["verdict"] = _CHALLENGE
                else:
                    record["verdict"] = _ALLOW
            parsed.append(record)

    return parsed


def weight_of(signal: Mapping[str, Any], policy: Mapping[str, Any]) -> float:
    """Return the reliability weight assigned to a signal source."""

    return 1.0


def resolve_conflict(signals: Any) -> str:
    """Resolve a mixed set of signal verdicts into one conclusion."""

    result = _ALLOW
    for signal in parse_signals(signals):
        verdict = signal.get("verdict")
        if verdict in _VERDICTS:
            result = verdict
    return result


def _is_weak(signal: Mapping[str, Any], policy: Mapping[str, Any], weight: float) -> bool:
    confidence = _number(signal.get("confidence"), 1.0)
    confidence_limit = _number(policy.get("weak_confidence_max"), 0.3)
    weight_limit = _number(policy.get("weak_weight_max"), 0.2)
    return confidence <= confidence_limit or weight <= weight_limit


def score(signals: Any, policy: Mapping[str, Any]) -> float:
    """Return the weighted risk score for the supplied signals."""

    parsed = parse_signals(signals)
    total = 0.0
    for signal in parsed:
        if signal.get("neutral"):
            continue
        weight = weight_of(signal, policy)
        total += _number(signal.get("value")) * weight
    return total


def decide(score: float, policy: Mapping[str, Any]) -> str:
    """Map a numeric risk score to allow, challenge or block."""

    value = _number(score, 0.0)
    challenge_threshold = _number(policy.get("challenge_threshold"), 30.0)
    block_threshold = _number(policy.get("block_threshold"), 70.0)

    if value > block_threshold:
        return _BLOCK
    if value > challenge_threshold:
        return _CHALLENGE
    return _ALLOW


def _dedupe_key(signal: Mapping[str, Any], session: Any) -> tuple[str, str]:
    signal_session = signal.get("session")
    effective_session = signal_session if signal_session is not None else session
    return ("" if effective_session is None else str(effective_session), _text(signal.get("name")))


def dedupe(signals: Any, session: Any = None) -> list[dict[str, Any]]:
    """Remove repeated reports of the same signal for a session."""

    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for signal in parse_signals(signals):
        key = _text(signal.get("name"))
        if key in seen:
            continue
        seen.add(key)
        result.append(signal)
    return result


def validate_policy(policy: Mapping[str, Any]) -> list[str]:
    """Return a list of policy problem codes."""

    issues: list[str] = []
    if not isinstance(policy, Mapping):
        return ["invalid_policy"]

    weights = policy.get("source_weights")
    if not isinstance(weights, Mapping) or not weights:
        issues.append("missing_source_weights")
    else:
        for source, raw_weight in weights.items():
            if isinstance(raw_weight, bool) or not isinstance(raw_weight, (int, float)):
                issues.append(f"invalid_weight:{source}")
                continue
            weight = float(raw_weight)
            if not math.isfinite(weight) or weight < 0 or weight > 1:
                issues.append(f"invalid_weight:{source}")

    challenge = policy.get("challenge_threshold")
    block = policy.get("block_threshold")
    score_max = _number(policy.get("score_max"), 100.0)

    challenge_ok = (
        isinstance(challenge, (int, float))
        and not isinstance(challenge, bool)
        and math.isfinite(float(challenge))
    )
    block_ok = (
        isinstance(block, (int, float))
        and not isinstance(block, bool)
        and math.isfinite(float(block))
    )
    if not challenge_ok:
        issues.append("invalid_threshold:challenge_threshold")
    if not block_ok:
        issues.append("invalid_threshold:block_threshold")
    if challenge_ok and block_ok:
        challenge_value = float(challenge)
        block_value = float(block)
        if challenge_value < 0 or block_value > score_max:
            issues.append("threshold_out_of_range")

    if not policy.get("strict_rule"):
        issues.append("missing_strict_rule")

    return issues


def _session_items(sessions: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(sessions, Mapping):
        for session_id, signals in sessions.items():
            yield str(session_id), signals
        return

    for index, item in enumerate(sessions):
        if isinstance(item, Mapping):
            session_id = item.get("session_id", item.get("session", item.get("id", index)))
            yield str(session_id), item.get("signals", [])
        elif isinstance(item, (tuple, list)) and len(item) == 2:
            session_id, signals = item
            yield str(session_id), signals
        else:
            yield str(index), item


def bot_batch(sessions: Any, policy: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Evaluate several sessions and return one result per session."""

    results: dict[str, dict[str, Any]] = {}
    first_score: float | None = None
    for session_id, raw_signals in _session_items(sessions):
        unique = dedupe(raw_signals, session_id)
        if first_score is None:
            first_score = score(unique, policy)
        current_score = first_score
        results[session_id] = {
            "score": float(current_score),
            "decision": decide(current_score, policy),
            "signal_count": len(unique),
        }
    return results