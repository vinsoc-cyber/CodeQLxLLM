# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""#150: deterministic post-processing branches on the verdict envelope's
structured ``signals`` object, not on English phrasing.

Each downgrade pass prefers the model's structured self-report
(``line_citations``, ``pollution_scope``, ``path_source``,
``crosses_trust_boundary``) and falls back to the legacy phrase markers only
when the envelope carried no signal — so a paraphrase can no longer bypass a
guard, and old transcripts keep their behavior.
"""

from __future__ import annotations

from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.llm.client import _parsed_signals
from vuln_hunter_x.llm.prompts import PromptBuilder
from vuln_hunter_x.verification.engine import (
    _downgrade_cli_path_injection,
    _downgrade_local_prototype_pollution,
    _downgrade_unsupported_confidence,
)


def _verdict(
    verdict="True Positive",
    confidence="High",
    reasoning="r",
    rule_id="cpp/use-after-free",
    cwe_ids=(),
    lang="c",
    severity="",
    data_flow="",
    signals=None,
) -> Verdict:
    finding = Finding(
        rule_id=rule_id,
        message="m",
        file="a.c",
        start_line=1,
        end_line=1,
        repo_name="r",
        lang=lang,
        cwe_ids=list(cwe_ids),
        severity=severity,
    )
    return Verdict(
        finding=finding,
        verdict=verdict,
        confidence=confidence,
        reasoning=reasoning,
        answers=[],
        raw_response="",
        model="x",
        elapsed_seconds=0.0,
        iterations=1,
        confidence_score={"High": 0.85, "Medium": 0.6, "Low": 0.3}[confidence],
        data_flow=data_flow,
        signals=signals or {},
    )


class TestParsedSignals:
    def test_dict_passthrough(self):
        assert _parsed_signals({"signals": {"line_citations": True}}) == {
            "line_citations": True
        }

    def test_missing_or_malformed_is_empty(self):
        assert _parsed_signals({}) == {}
        assert _parsed_signals({"signals": "yes"}) == {}
        assert _parsed_signals({"signals": ["a"]}) == {}


class TestCitationSignal:
    def test_signal_false_downgrades_without_marker_phrases(self):
        # A paraphrase carrying none of the legacy markers used to bypass the
        # guard; the structured signal closes that gap.
        v = _verdict(reasoning="The dangerous call is present.",
                     signals={"line_citations": False})
        out = _downgrade_unsupported_confidence(v)
        assert out.confidence == "Low"

    def test_signal_true_suppresses_marker_heuristic(self):
        v = _verdict(reasoning="This is a textbook use-after-free pattern.",
                     signals={"line_citations": True})
        out = _downgrade_unsupported_confidence(v)
        assert out.confidence == "High"

    def test_actual_citation_still_wins_over_signal(self):
        # The objective line-citation scan is authoritative: evidence citing
        # line 42 is never downgraded, whatever the self-report says.
        v = _verdict(reasoning="The bounds check at line 42 prevents this.",
                     signals={"line_citations": False})
        out = _downgrade_unsupported_confidence(v)
        assert out.confidence == "High"

    def test_no_signal_falls_back_to_markers(self):
        v = _verdict(reasoning="This is a textbook use-after-free pattern.")
        out = _downgrade_unsupported_confidence(v)
        assert out.confidence == "Low"


class TestPollutionScopeSignal:
    def _v(self, reasoning, signals=None):
        return _verdict(
            reasoning=reasoning,
            rule_id="js/prototype-pollution",
            cwe_ids=["CWE-1321"],
            lang="javascript",
            signals=signals,
        )

    def test_instance_scope_downgrades_without_marker_phrases(self):
        v = self._v("Assigning the spread onto the fresh object.",
                    signals={"pollution_scope": "instance"})
        out = _downgrade_local_prototype_pollution(v)
        assert out.confidence == "Low"

    def test_global_scope_overrides_local_sounding_prose(self):
        v = self._v("Only this instance is discussed but the merge recurses.",
                    signals={"pollution_scope": "global"})
        out = _downgrade_local_prototype_pollution(v)
        assert out.confidence == "High"

    def test_no_signal_falls_back_to_markers(self):
        v = self._v("The change affects only this instance, not global.")
        out = _downgrade_local_prototype_pollution(v)
        assert out.confidence == "Low"


class TestPathSourceSignal:
    def _v(self, reasoning, data_flow="", signals=None):
        return _verdict(
            reasoning=reasoning,
            rule_id="cpp/path-injection",
            cwe_ids=["CWE-22"],
            data_flow=data_flow,
            signals=signals,
        )

    def test_cli_source_downgrades_without_marker_phrases(self):
        v = self._v("The filename flows into fopen unchecked.",
                    signals={"path_source": "cli"})
        out = _downgrade_cli_path_injection(v)
        assert out.confidence == "Low"

    def test_external_source_overrides_argv_prose(self):
        v = self._v("The value from argv-style parsing reaches open().",
                    data_flow="argv -> open",
                    signals={"path_source": "external"})
        out = _downgrade_cli_path_injection(v)
        assert out.confidence == "High"

    def test_boundary_true_suppresses_downgrade(self):
        v = self._v("Filename from the command line reaches fopen.",
                    data_flow="argv -> fopen",
                    signals={"path_source": "cli", "crosses_trust_boundary": True})
        out = _downgrade_cli_path_injection(v)
        assert out.confidence == "High"

    def test_no_signal_falls_back_to_markers(self):
        v = self._v("The filename comes from argv with no validation.",
                    data_flow="source: argv[i] -> fopen")
        out = _downgrade_cli_path_injection(v)
        assert out.confidence == "Low"


def test_system_prompt_declares_signals_contract():
    prompt = PromptBuilder().get_system_prompt()
    assert '"signals"' in prompt
    for field in ("line_citations", "pollution_scope", "path_source",
                  "crosses_trust_boundary"):
        assert field in prompt
