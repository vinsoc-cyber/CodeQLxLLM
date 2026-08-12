"""#150: single-pass verification must be reproducible run-to-run.

Covers the two mechanisms: greedy decoding by default (temperature 0) and a
fixed ``seed`` on every completion, with per-sample derived seeds on the
self-consistency voting path so its output diversity is preserved.
"""

import threading

from vuln_hunter_x.core.config import Config, LLMConfig
from vuln_hunter_x.core.constants import DEFAULT_LLM_SEED, DEFAULT_LLM_TEMPERATURE
from vuln_hunter_x.core.types import Finding, GuidedQuestions, Verdict
from vuln_hunter_x.llm.client import LLMClient

MSGS = [{"role": "user", "content": "ok"}]


def _mk_finding() -> Finding:
    return Finding(
        rule_id="test-rule-1",
        message="m",
        file="a.py",
        start_line=1,
        end_line=1,
        repo_name="test-repo",
        lang="python",
    )


def _mk_verdict(finding: Finding, label: str) -> Verdict:
    return Verdict(
        finding=finding,
        verdict=label,
        confidence="Medium",
        reasoning="r",
        answers=[],
        raw_response="raw",
        model="fake",
        elapsed_seconds=0.0,
        iterations=1,
        tokens_used=1,
        cost_usd=0.0,
        confidence_score=0.6,
    )


def test_default_temperature_is_greedy():
    assert DEFAULT_LLM_TEMPERATURE == 0.0
    client = LLMClient(provider="openai", model="gpt-4o")
    kwargs = client._build_completion_kwargs(MSGS)
    assert kwargs["temperature"] == 0.0


def test_completion_kwargs_carry_fixed_seed_by_default():
    client = LLMClient(provider="openai", model="gpt-4o")
    kwargs = client._build_completion_kwargs(MSGS)
    assert kwargs["seed"] == DEFAULT_LLM_SEED


def test_seed_none_disables_seeding():
    client = LLMClient(provider="openai", model="gpt-4o", seed=None)
    kwargs = client._build_completion_kwargs(MSGS)
    assert "seed" not in kwargs


def test_per_call_seed_overrides_client_seed():
    client = LLMClient(provider="openai", model="gpt-4o", seed=7)
    assert client._build_completion_kwargs(MSGS, seed=99)["seed"] == 99
    # An explicit None requests provider entropy even on a seeded client.
    assert "seed" not in client._build_completion_kwargs(MSGS, seed=None)


def test_identical_input_builds_identical_kwargs():
    """The full completion request — not just the seed — must be stable
    across repeated builds for the same input."""
    client = LLMClient(provider="openai", model="gpt-4o")
    assert client._build_completion_kwargs(MSGS) == client._build_completion_kwargs(MSGS)


def test_voting_samples_get_distinct_derived_seeds():
    """Voting keeps diversity across samples (distinct seeds) while the vote
    as a whole stays reproducible (seeds derived from the fixed base)."""
    client = LLMClient(provider="openai", model="gpt-4o", seed=100)
    finding = _mk_finding()
    seen: list[tuple[int | None, float | None]] = []
    lock = threading.Lock()

    def fake_analyze(*, seed=None, temperature=None, finding=None, **_kwargs) -> Verdict:
        with lock:
            seen.append((seed, temperature))
        return _mk_verdict(finding, "False Positive")

    client.analyze = fake_analyze  # type: ignore[method-assign]
    client.analyze_with_voting(
        finding,
        "ctx",
        GuidedQuestions(rule_id="test", short_description="d", questions=["q"]),
        "f",
        samples=3,
        voting_temperature=0.7,
    )
    assert [s for s, _ in seen] == [100, 101, 102]
    assert all(t == 0.7 for _, t in seen)


def test_voting_samples_unseeded_when_client_seed_disabled():
    client = LLMClient(provider="openai", model="gpt-4o", seed=None)
    finding = _mk_finding()
    seen: list[int | None] = []

    def fake_analyze(*, seed="MISSING", finding=None, **_kwargs) -> Verdict:
        seen.append(seed)
        return _mk_verdict(finding, "False Positive")

    client.analyze = fake_analyze  # type: ignore[method-assign]
    client.analyze_with_voting(
        finding,
        "ctx",
        GuidedQuestions(rule_id="test", short_description="d", questions=["q"]),
        "f",
        samples=2,
        voting_temperature=0.7,
    )
    assert seen == [None, None]


def test_llm_config_parses_seed():
    assert LLMConfig().seed == DEFAULT_LLM_SEED
    cfg = Config.from_dict({"seed": 7})
    assert cfg.llm.seed == 7
    # YAML ``seed: null`` disables seeding.
    cfg_off = Config.from_dict({"seed": None})
    assert cfg_off.llm.seed is None
