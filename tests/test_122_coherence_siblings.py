# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""#122 residuals: verdict/reasoning coherence + sibling-construct consistency.

Coherence gate — a verdict label contradicting the reasoning's own explicit
conclusion (verdict=TP, reasoning "...so this specific finding is a false
positive", #162 signature.go:67) is held as Needs-More-Data.

Sibling gate — normalized-identical constructs under the same rule in the same
file (`eval(req.body.roth)` vs `eval(req.body.preTax)`) must not ship opposite
verdicts: the dismissal is held, naming the confirmed sibling. Abstain-only in
both gates.
"""

from __future__ import annotations

from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.verification.engine import (
    _COHERENCE_GATE,
    _SIBLING_GATE,
    _construct_shape,
    _flag_sibling_contradictions,
    _hold_incoherent_verdict,
)


def _finding(file="app/routes/contributions.js", line=32, snippet="", rule="js/code-injection"):
    return Finding(
        rule_id=rule, message="m", file=file, start_line=line, end_line=line,
        repo_name="nodegoat", lang="javascript", sink_snippet=snippet,
    )


def _verdict(label, reasoning="r", finding=None, source="legacy_model", confidence="High"):
    return Verdict(
        finding=finding or _finding(), verdict=label, confidence=confidence,
        reasoning=reasoning, answers=[], raw_response="{}", model="m",
        confidence_score={"High": 0.9, "Medium": 0.6, "Low": 0.3}[confidence],
        decision_source=source,
    )


# ── coherence gate ────────────────────────────────────────────────────

def test_tp_with_fp_conclusion_held():
    v = _verdict(
        "True Positive",
        "The reported sink line is misidentified, so this specific finding "
        "is a false positive.",
    )
    out = _hold_incoherent_verdict(v)
    assert out.verdict == "Needs More Data"
    assert out.decision_source == _COHERENCE_GATE
    assert "coherence_gate" in out.reasoning


def test_fp_with_tp_conclusion_held():
    v = _verdict("False Positive", "Tracing the flow shows this is a real vulnerability.")
    out = _hold_incoherent_verdict(v)
    assert out.verdict == "Needs More Data"


def test_negated_conclusion_does_not_fire():
    v = _verdict("True Positive", "The guard is dead code, so this is not a false positive.")
    assert _hold_incoherent_verdict(v).verdict == "True Positive"


def test_label_matching_conclusion_untouched():
    v = _verdict("False Positive", "intval() sanitises the id, so this is a false positive.")
    assert _hold_incoherent_verdict(v).verdict == "False Positive"


def test_plain_reasoning_untouched():
    v = _verdict("True Positive", "Tainted id reaches the query at line 35 unsanitised.")
    assert _hold_incoherent_verdict(v).verdict == "True Positive"


def test_nmd_and_policy_verdicts_untouched():
    assert _hold_incoherent_verdict(
        _verdict("Needs More Data", "is a false positive")
    ).verdict == "Needs More Data"
    assert _hold_incoherent_verdict(
        _verdict("True Positive", "is a false positive", source="policy")
    ).verdict == "True Positive"


# ── construct shape ───────────────────────────────────────────────────

def test_identifier_only_diff_shares_shape():
    a = _construct_shape("const roth = eval(req.body.roth);")
    b = _construct_shape("const preTax = eval(req.body.preTax);")
    assert a == b != ""


def test_call_names_are_kept_apart():
    a = _construct_shape("const roth = eval(req.body.roth);")
    b = _construct_shape("const roth = parseInt(req.body.roth);")
    assert a != b


def test_strings_and_numbers_masked():
    a = _construct_shape("query('SELECT 1', id)")
    b = _construct_shape('query("SELECT 2", uid)')
    assert a == b


def test_empty_snippet_has_no_shape():
    assert _construct_shape("") == ""


# ── sibling contradiction pass ────────────────────────────────────────

def _sibling_verdicts(labels, rule="js/code-injection"):
    out = []
    for i, label in enumerate(labels):
        f = _finding(
            line=32 + i,
            snippet=f"const v{i} = eval(req.body.f{i});",
            rule=rule,
        )
        out.append(_verdict(label, finding=f))
    return out


def test_dismissal_contradicting_confirmed_sibling_is_held():
    vs = _sibling_verdicts(["True Positive", "False Positive", "True Positive"])
    out = _flag_sibling_contradictions(vs)
    assert out[1].verdict == "Needs More Data"
    assert out[1].decision_source == _SIBLING_GATE
    assert "app/routes/contributions.js:32" in out[1].reasoning
    # the confirmed side is never demoted
    assert out[0].verdict == out[2].verdict == "True Positive"


def test_tp_plus_nmd_group_untouched():
    vs = _sibling_verdicts(["True Positive", "Needs More Data"])
    out = _flag_sibling_contradictions(vs)
    assert out[1].verdict == "Needs More Data"
    assert out[1].decision_source == "legacy_model"


def test_agreeing_group_untouched():
    vs = _sibling_verdicts(["False Positive", "False Positive"])
    out = _flag_sibling_contradictions(vs)
    assert all(v.verdict == "False Positive" for v in out)


def test_different_rules_do_not_group():
    a = _verdict("True Positive",
                 finding=_finding(line=32, snippet="x = eval(req.body.a);"))
    b = _verdict("False Positive",
                 finding=_finding(line=33, snippet="y = eval(req.body.b);",
                                  rule="js/other-rule"))
    out = _flag_sibling_contradictions([a, b])
    assert out[1].verdict == "False Positive"


def test_policy_verdicts_never_touched():
    a = _verdict("True Positive",
                 finding=_finding(line=32, snippet="x = eval(req.body.a);"))
    b = _verdict("False Positive", source="policy",
                 finding=_finding(line=33, snippet="y = eval(req.body.b);"))
    out = _flag_sibling_contradictions([a, b])
    assert out[1].verdict == "False Positive"


def test_snippetless_findings_never_group():
    a = _verdict("True Positive", finding=_finding(line=32, snippet=""))
    b = _verdict("False Positive", finding=_finding(line=33, snippet=""))
    out = _flag_sibling_contradictions([a, b])
    assert out[1].verdict == "False Positive"
