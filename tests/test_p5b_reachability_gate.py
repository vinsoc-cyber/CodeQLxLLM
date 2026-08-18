# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P5b engine transform: withhold a TP whose exact enclosing function is
test-only (recorded test callers + zero non-test references). Abstain-only —
TP->NMD, never ->FP. Unit-tested against a scripted provider; no LLM.

Originally Go CWE-208 (#174), then every Go CWE, then (#162) every language
with an unambiguous declaration keyword — go, python, javascript/typescript,
php. java/csharp/c/cpp still abstain by construction.
"""

from __future__ import annotations

from pathlib import Path

from vuln_hunter_x.context.evidence import (
    CallerRef,
    EvidenceStatus,
    RecordedCallersResult,
    ReferenceScanResult,
    SourceRef,
    SymbolRef,
    SymbolResolution,
)
from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.verification.engine import (
    _REACHABILITY_GATE,
    _downgrade_test_only_reachability,
)

_SIG = "internal/crypto/signature.go"


def _sym(name="verifySig", file=_SIG, status=EvidenceStatus.FOUND):
    symbol = SymbolRef(name, "function", SourceRef("svc", "go", file, 3, 5)) if name else None
    return SymbolResolution(status, symbol)


def _callers(files=("internal/crypto/a_test.go",), status=EvidenceStatus.FOUND, enumerated=True):
    target = SymbolRef("verifySig", "function", SourceRef("svc", "go", _SIG, 3, 5))
    return RecordedCallersResult(
        status, target,
        tuple(CallerRef("T", SourceRef("svc", "go", f, 10, 20)) for f in files),
        enumerated_all_rows=enumerated,
    )


def _scan(status=EvidenceStatus.NOT_FOUND_COMPLETE):
    target = SymbolRef("verifySig", "function", SourceRef("svc", "go", _SIG, 3, 5))
    return ReferenceScanResult(status, target, (), scan_complete=True)


class _FakeProvider(ContextProvider):
    def __init__(self, sym=None, callers=None, scan=None):
        super().__init__(Path("/nonexistent"), Path("/nonexistent"))
        self._sym = sym if sym is not None else _sym()
        self._callers = callers if callers is not None else _callers()
        self._scan = scan if scan is not None else _scan()
        self.calls = 0

    def resolve_repo_unique_enclosing_function(self, *a, **k):
        self.calls += 1
        return self._sym

    def resolve_all_recorded_callers(self, *a, **k):
        self.calls += 1
        return self._callers

    def scan_non_test_name_occurrences(self, *a, **k):
        self.calls += 1
        return self._scan


def _finding(lang="go", cwes=("CWE-208",)):
    return Finding(
        rule_id="go/timing-unsafe-comparison", message="timing-unsafe comparison",
        file=_SIG, start_line=4, end_line=4, repo_name="svc", lang=lang, cwe_ids=list(cwes),
    )


def _tp(*, confidence="High", score=0.9, source="legacy_model", verdict="True Positive", finding=None):
    return Verdict(
        finding=finding or _finding(), verdict=verdict, confidence=confidence,
        reasoning="secret compared with ==", answers=[], raw_response="{}", model="m",
        confidence_score=score, decision_source=source,
    )


def _run(verdict, provider, line=4):
    return _downgrade_test_only_reachability(verdict, verdict.finding, provider, line)


# ---- fires ----

def test_go_cwe208_tp_all_test_callers_no_prod_ref_downgrades():
    v = _run(_tp(), _FakeProvider())
    assert v.verdict == "Needs More Data"
    assert v.decision_source == _REACHABILITY_GATE
    assert v.confidence == "Low"
    assert v.confidence_score <= 0.3
    assert "reachability_gate" in v.reasoning


def test_exported_and_method_targets_also_downgrade():
    for name in ("VerifySig", "Verify"):
        v = _run(_tp(), _FakeProvider(sym=_sym(name=name)))
        assert v.verdict == "Needs More Data", name


# ---- does not fire (unchanged) ----

def test_production_caller_unchanged():
    prov = _FakeProvider(callers=_callers(files=("internal/crypto/crypto.go",)))
    v = _run(_tp(), prov)
    assert v.verdict == "True Positive"


def test_mixed_test_and_prod_callers_unchanged():
    prov = _FakeProvider(callers=_callers(files=("a_test.go", "crypto.go")))
    v = _run(_tp(), prov)
    assert v.verdict == "True Positive"


def test_prod_reference_veto_unchanged():
    prov = _FakeProvider(scan=_scan(status=EvidenceStatus.FOUND))
    v = _run(_tp(), prov)
    assert v.verdict == "True Positive"


def test_empty_callers_unchanged():
    prov = _FakeProvider(callers=_callers(files=(), status=EvidenceStatus.INCOMPLETE_INDEX))
    v = _run(_tp(), prov)
    assert v.verdict == "True Positive"


def test_truncated_enumeration_unchanged():
    prov = _FakeProvider(callers=_callers(enumerated=False))
    v = _run(_tp(), prov)
    assert v.verdict == "True Positive"


def test_ambiguous_resolution_unchanged():
    prov = _FakeProvider(sym=_sym(status=EvidenceStatus.AMBIGUOUS))
    v = _run(_tp(), prov)
    assert v.verdict == "True Positive"


def test_main_and_init_excluded():
    for name in ("main", "init"):
        prov = _FakeProvider(sym=_sym(name=name))
        v = _run(_tp(), prov)
        assert v.verdict == "True Positive", name


def test_target_in_test_file_unchanged():
    prov = _FakeProvider(sym=_sym(file="internal/crypto/signature_test.go"))
    v = _run(_tp(), prov)
    assert v.verdict == "True Positive"


def test_unsupported_language_not_touched_and_provider_not_called():
    """java/csharp/c/cpp declarations lead with modifiers and a return type, so
    no precise single declaration token can be located; the gate must abstain
    before touching the provider at all.

    Was ``test_non_go_not_touched_and_provider_not_called``: #162 widened the
    gate past Go, so ``python`` is now gated (see
    ``test_supported_languages_are_gated``) and no longer demonstrates neutrality.
    """
    for lang in ("java", "csharp", "c", "cpp"):
        prov = _FakeProvider()
        v = _run(_tp(finding=_finding(lang=lang)), prov)
        assert v.verdict == "True Positive", lang
        assert prov.calls == 0, lang


def test_non_cwe208_go_findings_also_gated():
    # #162 widened the gate from CWE-208 to every Go CWE: the evidence guards
    # (unique symbol, all-test callers, zero non-test references) are
    # class-independent, so a test-only SQL-injection TP abstains the same way.
    prov = _FakeProvider()
    v = _run(_tp(finding=_finding(cwes=("CWE-89",))), prov)
    assert v.verdict == "Needs More Data"
    assert v.decision_source == _REACHABILITY_GATE


def test_fp_and_nmd_unchanged_provider_not_called():
    for vt in ("False Positive", "Needs More Data"):
        prov = _FakeProvider()
        v = _run(_tp(verdict=vt), prov)
        assert v.verdict == vt
        assert prov.calls == 0


def test_policy_sourced_verdict_not_touched():
    prov = _FakeProvider()
    v = _run(_tp(source="policy"), prov)
    assert v.verdict == "True Positive"
    assert prov.calls == 0


def test_snippet_provider_not_touched():
    # a non-ContextProvider (no reachability data) leaves the verdict unchanged
    v = _run(_tp(), provider=object())
    assert v.verdict == "True Positive"


def test_reachability_gate_round_trips():
    v = _run(_tp(), _FakeProvider())
    restored = Verdict.from_dict(v.to_dict())
    assert restored.decision_source == _REACHABILITY_GATE


# ---- #162: the gate now covers every language with an unambiguous decl keyword ----

def _lang_sym(name, lang, file):
    return SymbolResolution(
        EvidenceStatus.FOUND, SymbolRef(name, "function", SourceRef("svc", lang, file, 3, 5))
    )


def _lang_callers(name, lang, files):
    target = SymbolRef(name, "function", SourceRef("svc", lang, "x", 3, 5))
    return RecordedCallersResult(
        EvidenceStatus.FOUND, target,
        tuple(CallerRef("T", SourceRef("svc", lang, f, 10, 20)) for f in files),
        enumerated_all_rows=True,
    )


_SUPPORTED_CASES = [
    # (lang, decl file, test-caller files)
    ("python", "app/crypto/signature.py", ("app/crypto/test_signature.py",)),
    ("python", "app/crypto/signature.py", ("app/crypto/signature_test.py",)),
    ("javascript", "src/crypto/signature.js", ("src/crypto/signature.test.js",)),
    ("javascript", "src/crypto/signature.ts", ("src/crypto/signature.spec.ts",)),
    ("typescript", "src/crypto/signature.ts", ("src/crypto/signature.test.tsx",)),
    ("php", "src/Crypto/Signature.php", ("tests/Crypto/SignatureTest.php",)),
    ("go", _SIG, ("internal/crypto/a_test.go",)),
]


def test_supported_languages_are_gated():
    """A test-only enclosing function abstains in every supported language.

    This is the #162 residual: the gate previously returned early for anything
    that was not Go, so a TS/JS or Python function reached only from its own
    test file stayed a confirmed True Positive.
    """
    for lang, decl_file, caller_files in _SUPPORTED_CASES:
        prov = _FakeProvider(
            sym=_lang_sym("verifySig", lang, decl_file),
            callers=_lang_callers("verifySig", lang, caller_files),
        )
        v = _run(_tp(finding=_finding(lang=lang)), prov)
        assert v.verdict == "Needs More Data", (lang, decl_file, caller_files)
        assert v.decision_source == _REACHABILITY_GATE, lang
        assert "test-file references/callers" in v.reasoning, lang


def test_supported_languages_production_caller_unchanged():
    """One non-test caller in the same language leaves the TP standing."""
    cases = [
        ("python", "app/crypto/signature.py", ("app/crypto/handler.py",)),
        ("javascript", "src/crypto/signature.ts", ("src/crypto/handler.ts",)),
        ("php", "src/Crypto/Signature.php", ("src/Crypto/Handler.php",)),
    ]
    for lang, decl_file, caller_files in cases:
        prov = _FakeProvider(
            sym=_lang_sym("verifySig", lang, decl_file),
            callers=_lang_callers("verifySig", lang, caller_files),
        )
        v = _run(_tp(finding=_finding(lang=lang)), prov)
        assert v.verdict == "True Positive", (lang, caller_files)


def test_enclosing_function_in_test_file_unchanged_per_language():
    """A sink already inside a test file is out of scope for this gate.

    Guards the language-aware replacement of the old ``endswith('_test.go')``
    check on the enclosing function's own file.
    """
    cases = [
        ("python", "app/crypto/test_signature.py"),
        ("python", "app/crypto/signature_test.py"),
        ("javascript", "src/crypto/signature.test.js"),
        ("typescript", "src/crypto/signature.spec.ts"),
        ("php", "tests/Crypto/SignatureTest.php"),
        ("go", "internal/crypto/signature_test.go"),
    ]
    for lang, decl_file in cases:
        prov = _FakeProvider(
            sym=_lang_sym("verifySig", lang, decl_file),
            callers=_lang_callers("verifySig", lang, (decl_file,)),
        )
        v = _run(_tp(finding=_finding(lang=lang)), prov)
        assert v.verdict == "True Positive", (lang, decl_file)


def test_mixed_test_and_production_callers_unchanged():
    """Every caller must be a test file; one production caller vetoes the gate."""
    prov = _FakeProvider(
        sym=_lang_sym("verifySig", "python", "app/crypto/signature.py"),
        callers=_lang_callers(
            "verifySig", "python",
            ("app/crypto/test_signature.py", "app/api/handler.py"),
        ),
    )
    assert _run(_tp(finding=_finding(lang="python")), prov).verdict == "True Positive"
