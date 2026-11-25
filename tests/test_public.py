"""Public contract tests for the bot-signal package."""

import pytest

from botscore import bot_batch, parse_signals, resolve_conflict, score

POLICY = {
    "source_weights": {
        "browser": 0.9,
        "behavior": 0.6,
        "proxy": 0.2,
        "automation": 1.0,
        "reputation": 0.5,
    },
    "challenge_threshold": 30.0,
    "block_threshold": 70.0,
    "score_min": 0.0,
    "score_max": 100.0,
    "strict_rule": "deny_overrides",
    "weak_confidence_max": 0.3,
    "weak_weight_max": 0.2,
    "unknown_source_weight": 0.5,
}


def test_public_01_parse_automation_signal() -> None:
    parsed = parse_signals(
        [
            {"name": "WebDriver", "value": "80", "source": "Automation", "confidence": 0.9},
            {"name": "MouseEntropy", "value": 20, "source": "browser", "confidence": 1.0},
        ]
    )

    assert [item["name"] for item in parsed] == ["webdriver", "mouseentropy"]
    assert parsed[0]["source"] == "automation"
    assert parsed[0]["value"] == 80.0
    assert parsed[0]["automation"] is True
    assert parsed[0]["neutral"] is False
    assert score(parsed, POLICY) > 0.0


def test_public_02_weighted_source_sum() -> None:
    signals = parse_signals(
        [
            {"name": "velocity", "value": 80, "source": "proxy", "confidence": 1.0},
            {"name": "entropy", "value": 80, "source": "browser", "confidence": 1.0},
        ]
    )

    assert score(signals, POLICY) == pytest.approx(88.0)


def test_public_03_conflict_uses_strictest_verdict() -> None:
    signals = parse_signals(
        [
            {
                "name": "headless",
                "value": 80,
                "source": "automation",
                "verdict": "block",
                "confidence": 1.0,
            },
            {
                "name": "human_like",
                "value": 10,
                "source": "behavior",
                "verdict": "allow",
                "confidence": 1.0,
            },
        ]
    )

    assert resolve_conflict(signals) == "block"


def test_public_04_score_is_clamped() -> None:
    signals = parse_signals(
        [
            {"name": "a", "value": 100, "source": "browser", "confidence": 1.0},
            {"name": "b", "value": 100, "source": "automation", "confidence": 1.0},
            {"name": "c", "value": 100, "source": "browser", "confidence": 1.0},
        ]
    )

    result = score(signals, POLICY)

    assert 0.0 <= result <= 100.0
    assert result == pytest.approx(100.0)


def test_public_05_batch_sessions_are_independent() -> None:
    sessions = [
        {
            "session_id": "s1",
            "signals": [
                {"name": "credential_stuffing", "value": 90, "source": "browser", "confidence": 1.0}
            ],
        },
        {
            "session_id": "s2",
            "signals": [
                {"name": "mouse_motion", "value": 5, "source": "browser", "confidence": 1.0}
            ],
        },
    ]

    result = bot_batch(sessions, POLICY)

    assert result["s1"]["decision"] == "block"
    assert result["s2"]["decision"] == "allow"
    assert result["s1"]["score"] > result["s2"]["score"]