# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""#119 residual over-confirms → two new evidence-closure families.

The construct-is-present pattern survived on the C/C++ CodeQL findings, which no
family owned: a `sizeof` on a pointer and a check-then-use pathname pair were
confirmed because the flagged construct existed and "no defense" could be cited
— even though the pointer width was only printed and the racing process held no
privilege the racer lacked. Both families make the CONSEQUENCE decisive.

Deterministic panel over the declarative core (selection, entailment,
admissibility) plus a scripted end-to-end closure run, keyed to the cases from
the issue:

  pointer_sizeof (CWE-467)
    - pointer width only printed (practice/decay.cpp:5)                  -> FP
    - pointer width is the intended measure of a pointer-sized field     -> FP
    - flagged operand is an in-scope array, not a pointer                -> FP
    - pointer width bounds an undersized copy                            -> TP
  toctou_race (CWE-367)
    - standalone CLI racing its own invoker's argv path (main.c:135)     -> FP
    - the use is bound to the checked descriptor on every path           -> FP
    - a privileged daemon re-opening a path by name                      -> TP
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from vuln_hunter_x.context.evidence import SourceRef
from vuln_hunter_x.core.types import Finding, GuidedQuestions
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.verification.policy.closure import PolicyClosureController
from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.ledger import (
    EvidenceEntry,
    EvidenceLedger,
    EvidenceOrigin,
)
from vuln_hunter_x.verification.policy.loader import load_policy_registry
from vuln_hunter_x.verification.policy.models import FP, NMD, TP
from vuln_hunter_x.verification.policy.support import is_admissible

_SIZEOF_RULE = "cpp/suspicious-sizeof"
_TOCTOU_RULE = "cpp/toctou-race-condition"

_REG = load_policy_registry()
_SIZEOF = _REG.resolve_family(cwe_ids=["CWE-467"], rule_id=_SIZEOF_RULE, lang="cpp")
_TOCTOU = _REG.resolve_family(cwe_ids=["CWE-367"], rule_id=_TOCTOU_RULE, lang="c")


# ── selection ─────────────────────────────────────────────────────────

def test_families_load_and_select_the_uncovered_codeql_rules():
    assert _SIZEOF is not None and _SIZEOF.family == "pointer_sizeof"
    assert _TOCTOU is not None and _TOCTOU.family == "toctou_race"


def test_selection_by_rule_alias_without_a_cwe_tag():
    # A SARIF run that carries no CWE tag still routes on the rule id.
    assert _REG.resolve_family(
        cwe_ids=[], rule_id=_SIZEOF_RULE, lang="cpp"
    ).family == "pointer_sizeof"
    assert _REG.resolve_family(
        cwe_ids=[], rule_id=_TOCTOU_RULE, lang="c"
    ).family == "toctou_race"


def test_families_are_language_agnostic():
    # The arguments are about the construct's consequence, not the syntax: a
    # Go/Java TOCTOU rule selects the same family.
    assert _REG.resolve_family(
        cwe_ids=["CWE-367"], rule_id="go/toctou-race-condition", lang="go"
    ).family == "toctou_race"


def test_thread_race_conditions_stay_out():
    # CWE-362 (concurrent access to shared state) is a different family: no
    # filesystem check-then-use pair, no pathname rebinding.
    assert _REG.resolve_family(
        cwe_ids=["CWE-362"], rule_id="py/async-race-condition", lang="python"
    ) is None


def test_no_overlap_with_existing_families():
    # Every bundled family's own selectors still resolve to exactly that family
    # (resolve_family raises PolicyOverlapError on any overlap).
    for policy in _REG._policies:
        lang = next(iter(sorted(policy.languages)), "")
        for cwe in sorted(policy.cwes):
            resolved = _REG.resolve_family(cwe_ids=[cwe], rule_id="", lang=lang)
            assert resolved is not None and resolved.family == policy.family


def test_engine_routes_both_rules_to_the_policy_path():
    # Selection is only half the fix: the engine must take these findings off the
    # legacy model-verdict path, where "the construct is present" was enough.
    from vuln_hunter_x.core.config import load_config
    from vuln_hunter_x.verification.engine import VerificationEngine

    engine = VerificationEngine(load_config())
    assert engine._is_policy_routed(
        _finding(_SIZEOF_RULE, "CWE-467", "insecure-coding-examples", "cpp",
                 "practice/decay.cpp", 5, [])
    )
    assert engine._is_policy_routed(
        _finding(_TOCTOU_RULE, "CWE-367", "fuzzgoat", "c", "main.c", 135, [])
    )
    # An unrelated C++ rule keeps its legacy route.
    assert not engine._is_policy_routed(
        _finding("cpp/use-after-free", "CWE-416", "fuzzgoat", "cpp", "main.c", 20, [])
    )


# ── pointer_sizeof entailment ─────────────────────────────────────────

def test_pointer_width_only_printed_dismisses():
    # practice/decay.cpp:5 — the exact #119 over-confirm: `std::cout <<
    # sizeof(ages)` bounds nothing.
    d = entail(_SIZEOF, {
        "sink_binding": "SIZEOF_ON_POINTER",
        "size_consequence": "NO_MEMORY_CONSEQUENCE",
    })
    assert d.verdict is FP
    assert "size_consequence" in (d.terminal_reason or "")


def test_pointer_width_is_the_intended_measure_dismisses():
    d = entail(_SIZEOF, {
        "sink_binding": "SIZEOF_ON_POINTER",
        "size_consequence": "BOUNDS_MEMORY_OPERATION",
        "size_correctness": "CORRECT_FOR_OPERATION",
    })
    assert d.verdict is FP


def test_mislocated_sizeof_dismisses():
    # The operand is an in-scope array (no decay), so the rule's premise fails.
    assert entail(_SIZEOF, {"sink_binding": "NOT_SIZEOF_ON_POINTER"}).verdict is FP


def test_undersized_copy_confirms():
    d = entail(_SIZEOF, {
        "sink_binding": "SIZEOF_ON_POINTER",
        "size_consequence": "BOUNDS_MEMORY_OPERATION",
        "size_correctness": "UNDERSIZED_FOR_OPERATION",
    })
    assert d.verdict is TP


def test_sizeof_unresolved_consequence_is_honest_nmd():
    d = entail(_SIZEOF, {"sink_binding": "SIZEOF_ON_POINTER"})
    assert d.verdict is NMD
    assert "size_consequence" in (d.terminal_reason or "")


def test_absence_of_a_defense_alone_never_confirms():
    # There is no sanitizer for `sizeof`: the construct plus "nothing guards it"
    # leaves every consequence slot unresolved, which is NMD, not TP.
    assert entail(_SIZEOF, {"sink_binding": "SIZEOF_ON_POINTER"}).verdict is not TP


# ── toctou_race entailment ────────────────────────────────────────────

def test_operator_owned_path_dismisses():
    # main.c:135 — stat/fopen on the invoker's own argv path in a standalone
    # binary: the racer already owns the file.
    d = entail(_TOCTOU, {
        "sink_binding": "CHECK_THEN_USE_PRESENT",
        "binding_coverage": "PATHNAME_REBOUND",
        "privilege_boundary": "NO_BOUNDARY",
    })
    assert d.verdict is FP
    assert "privilege_boundary" in (d.terminal_reason or "")


def test_handle_bound_use_dismisses():
    d = entail(_TOCTOU, {
        "sink_binding": "CHECK_THEN_USE_PRESENT",
        "binding_coverage": "HANDLE_BOUND_ALL_PATHS",
        "privilege_boundary": "BOUNDARY_CROSSED",
    })
    assert d.verdict is FP


def test_mislocated_check_then_use_dismisses():
    assert entail(_TOCTOU, {"sink_binding": "NOT_PRESENT"}).verdict is FP


def test_privileged_rebind_confirms():
    d = entail(_TOCTOU, {
        "sink_binding": "CHECK_THEN_USE_PRESENT",
        "binding_coverage": "PATHNAME_REBOUND",
        "privilege_boundary": "BOUNDARY_CROSSED",
    })
    assert d.verdict is TP


def test_toctou_unresolved_boundary_is_honest_nmd():
    d = entail(_TOCTOU, {
        "sink_binding": "CHECK_THEN_USE_PRESENT",
        "binding_coverage": "PATHNAME_REBOUND",
    })
    assert d.verdict is NMD
    assert "privilege_boundary" in (d.terminal_reason or "")


# ── admissibility ─────────────────────────────────────────────────────

_LOCAL = EvidenceEntry(id="L1", origin=EvidenceOrigin.LOCAL_SLICE, summary="line 5")
_DATAFLOW = EvidenceEntry(id="D1", origin=EvidenceOrigin.SCANNER_DATAFLOW, summary="flow")


def test_local_slice_admits_the_inert_use_dismissal():
    # The whole consumption of the value is on the flagged line itself.
    assert is_admissible(_SIZEOF, "size_consequence", "NO_MEMORY_CONSEQUENCE", [_LOCAL])
    assert is_admissible(_SIZEOF, "sink_binding", "SIZEOF_ON_POINTER", [_LOCAL])


def test_dataflow_alone_cannot_establish_inert_use():
    # NO_MEMORY_CONSEQUENCE is an all-consumers claim; a single scanner relation
    # is not coverage over every use.
    assert not is_admissible(
        _SIZEOF, "size_consequence", "NO_MEMORY_CONSEQUENCE", [_DATAFLOW]
    )
    assert is_admissible(_SIZEOF, "size_consequence", "BOUNDS_MEMORY_OPERATION", [_DATAFLOW])


def test_local_slice_admits_the_boundary_facts():
    assert is_admissible(_TOCTOU, "privilege_boundary", "NO_BOUNDARY", [_LOCAL])
    assert is_admissible(_TOCTOU, "binding_coverage", "PATHNAME_REBOUND", [_LOCAL])


def test_dataflow_alone_cannot_establish_handle_binding():
    assert not is_admissible(
        _TOCTOU, "binding_coverage", "HANDLE_BOUND_ALL_PATHS", [_DATAFLOW]
    )


def test_uncited_values_fail_closed():
    assert not is_admissible(_SIZEOF, "size_consequence", "BOUNDS_MEMORY_OPERATION", [])
    assert not is_admissible(_TOCTOU, "privilege_boundary", "BOUNDARY_CROSSED", [])


# ── end-to-end closure over the two issue findings ────────────────────

def _finding(rule, cwe, repo, lang, file, line, flow):
    return Finding(
        rule_id=rule, message="m", file=file, start_line=line, end_line=line,
        repo_name=repo, lang=lang, cwe_ids=[cwe], dataflow_path=flow,
    )


def _seeded(finding, source_line):
    led = EvidenceLedger()
    led.add_local_slice(
        SourceRef(finding.repo_name, finding.lang, finding.file,
                  finding.start_line, finding.start_line + 1),
        source_line,
    )
    led.add_scanner_dataflow(" -> ".join(finding.dataflow_path))
    return led


def _resp(content):
    choice = MagicMock()
    choice.message.content = content
    r = MagicMock()
    r.choices = [choice]
    return r


def _run(mock_completion, policy, finding, source_line, slots):
    mock_completion.side_effect = [
        _resp(json.dumps({"fact_slots": slots, "reasoning": "assessed"}))
    ]
    controller = PolicyClosureController(
        policy=policy, provider=MagicMock(), finding=finding, model="gpt-4o",
        ledger=_seeded(finding, source_line),
    )
    client = LLMClient(provider="openai", model="gpt-4o")
    return client.analyze(
        finding=finding, context=source_line,
        questions=GuidedQuestions(rule_id=finding.rule_id, short_description="d",
                                  questions=["q?"]),
        func_name="f", force_decision=False, decision_strategy=controller,
        max_iterations=3, quiet=True,
    )


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_decay_cpp_printed_pointer_width_closes_as_fp(mc):
    finding = _finding(_SIZEOF_RULE, "CWE-467", "insecure-coding-examples", "cpp",
                       "practice/decay.cpp", 5, ["ages", "sizeof(ages)"])
    v = _run(mc, _SIZEOF, finding, "std::cout << sizeof(ages) << '\\n';", {
        "sink_binding": {"value": "SIZEOF_ON_POINTER", "evidence": ["L1"]},
        "size_consequence": {"value": "NO_MEMORY_CONSEQUENCE", "evidence": ["L1"]},
        "size_correctness": {"value": "UNRESOLVED", "evidence": []},
    })
    assert v.verdict == "False Positive"
    assert "pointer_sizeof" in v.reasoning


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_fuzzgoat_main_argv_race_closes_as_fp(mc):
    finding = _finding(_TOCTOU_RULE, "CWE-367", "fuzzgoat", "c",
                       "main.c", 135, ["argv[1]", "stat", "fopen"])
    v = _run(mc, _TOCTOU, finding, 'fp = fopen(filename, "rt");', {
        "sink_binding": {"value": "CHECK_THEN_USE_PRESENT", "evidence": ["L1"]},
        "binding_coverage": {"value": "PATHNAME_REBOUND", "evidence": ["L1"]},
        "privilege_boundary": {"value": "NO_BOUNDARY", "evidence": ["L1"]},
    })
    assert v.verdict == "False Positive"
    assert "toctou_race" in v.reasoning


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_unsubstantiated_confirmation_stays_needs_more_data(mc):
    # The over-confirm shape itself: the construct is claimed present and the
    # consequence slots are cited to nothing. Inadmissible -> NMD, never TP.
    finding = _finding(_SIZEOF_RULE, "CWE-467", "insecure-coding-examples", "cpp",
                       "practice/decay.cpp", 5, ["ages", "sizeof(ages)"])
    v = _run(mc, _SIZEOF, finding, "std::cout << sizeof(ages) << '\\n';", {
        "sink_binding": {"value": "SIZEOF_ON_POINTER", "evidence": ["L1"]},
        "size_consequence": {"value": "BOUNDS_MEMORY_OPERATION", "evidence": []},
        "size_correctness": {"value": "UNDERSIZED_FOR_OPERATION", "evidence": []},
    })
    assert v.verdict == "Needs More Data"


def test_overlays_render_the_consequence_slots():
    finding = _finding(_TOCTOU_RULE, "CWE-367", "fuzzgoat", "c",
                       "main.c", 135, ["argv[1]", "stat", "fopen"])
    controller = PolicyClosureController(
        policy=_TOCTOU, provider=MagicMock(), finding=finding, model="gpt-4o",
        ledger=_seeded(finding, 'fp = fopen(filename, "rt");'),
    )
    instr = controller.initial_instructions()
    assert "privilege_boundary" in instr and "binding_coverage" in instr
    assert "[L1]" in instr and "[D1]" in instr


def test_covered_rules_carry_no_verdict_command_into_the_assessment():
    # The guided questions are still rendered into the policy (assessment-mode)
    # prompt, so a rule that COMMANDS a verdict would bias the fact slots the
    # family exists to decide. Neither rule has a bank entry; both fall back to
    # the neutral default bank. Pinned so adding one later is a deliberate act.
    from pathlib import Path

    from vuln_hunter_x.questions.loader import QuestionsLoader

    loader = QuestionsLoader(Path(__file__).resolve().parents[1] / "config" / "prompts")
    for rule, cwe, lang in ((_SIZEOF_RULE, "CWE-467", "cpp"), (_TOCTOU_RULE, "CWE-367", "c")):
        questions, match = loader.get_questions_with_match_info(
            rule, cwe_ids=[cwe], lang=lang
        )
        assert match == "default", (rule, match)
        text = " ".join(questions.questions).lower()
        assert "verdict false positive" not in text
        assert "verdict true positive" not in text
        assert "the rule is likely correct" not in text
