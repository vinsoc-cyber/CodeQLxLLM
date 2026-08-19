# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Issue #162 reproduction: every finding the report listed, end-to-end.

The report ("Confirms findings in unreachable / test-only / mock code") listed
four over-confirmed findings on a private Go estate:

    internal/crypto/signature.go:67  test-only enclosing fn  TP -> FP
    internal/crypto/signature.go:86  superseded v1 verifier  TP -> FP
    cmd/mockserver/main.go:332       standalone dev/mock main TP -> FP
    cmd/mockserver/main.go:361       standalone dev/mock main TP -> FP

Each is reproduced here against the REAL ContextProvider (functions.csv +
callers.csv + on-disk source) and pushed through both post-verdict gates in the
same order ``_verify_legacy_finding`` applies them. Paths/identifiers are the
generic ones from the public report; the original target is private.

The gates abstain (Needs-More-Data) rather than dismiss (False Positive): a
static call graph cannot prove the absence of a production caller, so the
correct posture is withholding the confirmation, not asserting a non-bug. The
report itself allows this ("dismiss (or Needs-More-Data)").
"""

from __future__ import annotations

import csv

from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.verification.engine import (
    _downgrade_dev_mock_entrypoint,
    _downgrade_test_only_reachability,
)

_FUNC_COLS = ["name", "file", "start_line", "end_line", "param_count", "is_static"]
_CALLER_COLS = [
    "callee_name", "callee_file", "caller_name",
    "caller_file", "caller_start_line", "caller_end_line",
]

_SIG = "internal/crypto/signature.go"
_SIG_TEST = "internal/crypto/signature_test.go"
_MOCK = "cmd/mockserver/main.go"

# Two verifiers in one file: verifySigV1 (line 67, superseded) and verifySigV2
# (line 86). Both are only referenced from signature_test.go.
_SIG_SRC = "\n".join(
    ["package crypto", ""]
    + [f"// pad {i}" for i in range(3, 66)]
    + [
        "func verifySigV1(sig, want string) bool {",   # 66
        "\treturn sig == want",                        # 67  <- reported sink
        "}",                                           # 68
    ]
    + [f"// pad {i}" for i in range(69, 85)]
    + [
        "func verifySigV2(sig, want string) bool {",   # 85
        "\treturn sig == want",                        # 86  <- reported sink
        "}",                                           # 87
    ]
) + "\n"

_SIG_TEST_SRC = (
    "package crypto\n\n"
    "func TestV1(t any) { verifySigV1(\"a\", \"b\") }\n"
    "func TestV2(t any) { verifySigV2(\"a\", \"b\") }\n"
)

_MOCK_SRC = "package main\n\nfunc main() {\n\ttoken := \"hardcoded\"\n\t_ = token\n}\n"


def _provider(tmp_path):
    """Real provider over a repo mirroring the reported layout."""
    out, repos = tmp_path / "output", tmp_path / "repos"
    ctx = out / "go" / "svc" / "context"
    ctx.mkdir(parents=True, exist_ok=True)
    functions = [
        {"name": "verifySigV1", "file": _SIG, "start_line": "66", "end_line": "68"},
        {"name": "verifySigV2", "file": _SIG, "start_line": "85", "end_line": "87"},
    ]
    callers = [
        {"callee_name": "verifySigV1", "callee_file": _SIG, "caller_name": "TestV1",
         "caller_file": _SIG_TEST, "caller_start_line": "3", "caller_end_line": "3"},
        {"callee_name": "verifySigV2", "callee_file": _SIG, "caller_name": "TestV2",
         "caller_file": _SIG_TEST, "caller_start_line": "4", "caller_end_line": "4"},
    ]
    with open(ctx / "functions.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_FUNC_COLS)
        w.writeheader()
        for r in functions:
            w.writerow({"param_count": "2", "is_static": "false", **r})
    with open(ctx / "callers.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_CALLER_COLS)
        w.writeheader()
        for r in callers:
            w.writerow(r)
    src = repos / "go" / "svc"
    for rel, text in ((_SIG, _SIG_SRC), (_SIG_TEST, _SIG_TEST_SRC), (_MOCK, _MOCK_SRC)):
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return ContextProvider(out, repos)


def _confirmed_tp(file, line, confidence="High"):
    finding = Finding(
        rule_id="codeql/go-timing-unsafe-comparison",
        message="Comparison of secret with == is timing-unsafe",
        file=file, start_line=line, end_line=line,
        repo_name="svc", lang="go", cwe_ids=["CWE-208"],
    )
    return finding, Verdict(
        finding=finding, verdict="True Positive", confidence=confidence,
        reasoning="a secret/token is compared with == and the comparison is timing-unsafe",
        answers=[], raw_response="{}", model="gpt-5.4-mini", confidence_score=0.9,
    )


def _apply_gates(verdict, finding, provider, line):
    """Both #162 gates, in the order _verify_legacy_finding applies them."""
    verdict = _downgrade_test_only_reachability(verdict, finding, provider, line)
    return _downgrade_dev_mock_entrypoint(verdict, finding)


# ---- the four reported findings ----

def test_signature_line_67_test_only_verifier_no_longer_confirmed(tmp_path):
    """signature.go:67 — enclosing fn's only callers are in *_test.go."""
    p = _provider(tmp_path)
    finding, verdict = _confirmed_tp(_SIG, 67, confidence="Medium")
    out = _apply_gates(verdict, finding, p, 67)
    assert out.verdict != "True Positive"
    assert out.verdict == "Needs More Data"
    assert out.decision_source == "reachability_gate"
    assert out.confidence_score <= 0.3


def test_signature_line_86_superseded_verifier_no_longer_confirmed(tmp_path):
    """signature.go:86 — superseded v1/v2 verifier, only *_test.go calls it."""
    p = _provider(tmp_path)
    finding, verdict = _confirmed_tp(_SIG, 86)
    out = _apply_gates(verdict, finding, p, 86)
    assert out.verdict == "Needs More Data"
    assert out.decision_source == "reachability_gate"


def test_mockserver_line_332_no_longer_confirmed(tmp_path):
    """cmd/mockserver/main.go:332 — one of the run's highest-confidence TPs."""
    p = _provider(tmp_path)
    finding, verdict = _confirmed_tp(_MOCK, 332)
    out = _apply_gates(verdict, finding, p, 332)
    assert out.verdict == "Needs More Data"
    assert out.decision_source == "reachability_gate"


def test_mockserver_line_361_no_longer_confirmed(tmp_path):
    """cmd/mockserver/main.go:361 — same standalone dev/mock binary."""
    p = _provider(tmp_path)
    finding, verdict = _confirmed_tp(_MOCK, 361)
    out = _apply_gates(verdict, finding, p, 361)
    assert out.verdict == "Needs More Data"
    assert out.decision_source == "reachability_gate"


# ---- negative control: production reachability must survive ----

def test_production_reachable_verifier_stays_confirmed(tmp_path):
    """A verifier called from a non-test file keeps its True Positive.

    The report's decisive complaint was that confirmations were *inverted*
    relative to reachability. Suppressing the unreachable variants is only
    correct if the reachable one is left standing — so this asserts the gates
    do not fire once a single production caller exists.
    """
    p = _provider(tmp_path)
    handler = p.repos_dir / "go" / "svc" / "internal" / "api" / "handler.go"
    handler.parent.mkdir(parents=True, exist_ok=True)
    handler.write_text(
        "package api\n\nfunc Handle() { verifySigV2(\"a\", \"b\") }\n", encoding="utf-8"
    )
    ctx = p.output_dir / "go" / "svc" / "context"
    with open(ctx / "callers.csv", "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=_CALLER_COLS).writerow({
            "callee_name": "verifySigV2", "callee_file": _SIG, "caller_name": "Handle",
            "caller_file": "internal/api/handler.go",
            "caller_start_line": "3", "caller_end_line": "3",
        })
    finding, verdict = _confirmed_tp(_SIG, 86)
    out = _apply_gates(verdict, finding, p, 86)
    assert out.verdict == "True Positive"
    assert out.confidence == "High"
