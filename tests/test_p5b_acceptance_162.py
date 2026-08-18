# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P5b acceptance (#162): the reachability gate end-to-end through the REAL
ContextProvider (functions.csv + callers.csv + real .go source) — resolve ->
enumerate -> scan -> withhold. Deterministic, no LLM. Abstain-only: TP->NMD,
never ->FP; anything uncertain leaves the verdict unchanged.
"""

from __future__ import annotations

import csv

from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.verification.engine import _downgrade_test_only_reachability

_FUNC_COLS = ["name", "file", "start_line", "end_line", "param_count", "is_static"]
_CALLER_COLS = [
    "callee_name", "callee_file", "caller_name",
    "caller_file", "caller_start_line", "caller_end_line",
]
_SIG = "internal/crypto/signature.go"
# verifySig on line 3 (aligns with the sink at line 4 below).
_DECL = "package crypto\n\nfunc verifySig(a, b string) bool {\n\treturn a == b\n}\n"
_TEST_SRC = "package crypto\n\nfunc TestVerify(t any) { verifySig(\"a\", \"b\") }\n"


def _repo(tmp_path, *, functions, callers=(), sources=None, repo="svc", lang="go"):
    out, repos = tmp_path / "output", tmp_path / "repos"
    ctx = out / lang / repo / "context"
    ctx.mkdir(parents=True, exist_ok=True)
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
    src_root = repos / lang / repo
    src_root.mkdir(parents=True, exist_ok=True)
    for rel, text in (sources or {}).items():
        p = src_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return ContextProvider(out, repos)


def _fn(name, file=_SIG, start=3, end=5):
    return {"name": name, "file": file, "start_line": str(start), "end_line": str(end)}


def _cr(caller, caller_file, callee="verifySig", callee_file=_SIG, s=10, e=20):
    return {
        "callee_name": callee, "callee_file": callee_file, "caller_name": caller,
        "caller_file": caller_file, "caller_start_line": str(s), "caller_end_line": str(e),
    }


def _finding(file=_SIG, lang="go", cwes=("CWE-208",)):
    return Finding(
        rule_id="go/timing-unsafe-comparison", message="timing", file=file,
        start_line=4, end_line=4, repo_name="svc", lang=lang, cwe_ids=list(cwes),
    )


def _gate(provider, finding, line=4):
    v = Verdict(
        finding=finding, verdict="True Positive", confidence="High",
        reasoning="secret compared with ==", answers=[], raw_response="{}", model="m",
        confidence_score=0.9,
    )
    return _downgrade_test_only_reachability(v, finding, provider, line)


# ---- the #162 core: dead function reached only from *_test.go ----

def test_eligible_test_only_downgrades_to_nmd(tmp_path):
    p = _repo(
        tmp_path,
        functions=[_fn("verifySig")],
        callers=[_cr("TestVerify", "internal/crypto/signature_test.go")],
        sources={_SIG: _DECL, "internal/crypto/signature_test.go": _TEST_SRC},
    )
    v = _gate(p, _finding())
    assert v.verdict == "Needs More Data"
    assert v.decision_source == "reachability_gate"


def test_exported_target_downgrades(tmp_path):
    decl = "package crypto\n\nfunc VerifySig(a, b string) bool {\n\treturn a == b\n}\n"
    test = "package crypto\n\nfunc TestV(t any){ VerifySig(\"a\",\"b\") }\n"
    p = _repo(
        tmp_path,
        functions=[_fn("VerifySig")],
        callers=[_cr("TestV", "internal/crypto/sig_test.go", callee="VerifySig")],
        sources={_SIG: decl, "internal/crypto/sig_test.go": test},
    )
    assert _gate(p, _finding()).verdict == "Needs More Data"


# ---- unchanged (production reachability visible or unresolved) ----

def test_production_caller_row_11_unchanged(tmp_path):
    callers = [_cr(f"T{i}", f"internal/crypto/s{i}_test.go") for i in range(10)]
    callers.append(_cr("Prod", "internal/crypto/live.go"))  # 11th, non-test
    p = _repo(
        tmp_path,
        functions=[_fn("verifySig")],
        callers=callers,
        sources={_SIG: _DECL, "internal/crypto/live.go": "package crypto\n\nfunc L(){ verifySig(\"a\",\"b\") }\n"},
    )
    assert _gate(p, _finding()).verdict == "True Positive"


def test_handlefunc_registration_unchanged(tmp_path):
    reg = "package crypto\n\nfunc route(){ HandleFunc(\"/x\", verifySig) }\n"
    p = _repo(
        tmp_path,
        functions=[_fn("verifySig")],
        callers=[_cr("TestVerify", "internal/crypto/signature_test.go")],
        sources={_SIG: _DECL, "internal/crypto/signature_test.go": _TEST_SRC, "internal/http/route.go": reg},
    )
    assert _gate(p, _finding()).verdict == "True Positive"


def test_same_line_decl_and_registration_unchanged(tmp_path):
    src = "package crypto\n\nfunc verifySig() { register(verifySig) }\n"
    p = _repo(
        tmp_path,
        functions=[_fn("verifySig", start=3, end=3)],
        callers=[_cr("TestVerify", "internal/crypto/signature_test.go")],
        sources={_SIG: src, "internal/crypto/signature_test.go": _TEST_SRC},
    )
    assert _gate(p, _finding()).verdict == "True Positive"


def test_caller_in_tests_dir_not_test_basename_unchanged(tmp_path):
    # caller_file basename is foo.go (NOT *_test.go) -> not test-exclusive.
    p = _repo(
        tmp_path,
        functions=[_fn("verifySig")],
        callers=[_cr("Helper", "internal/tests/foo.go")],
        sources={_SIG: _DECL},
    )
    assert _gate(p, _finding()).verdict == "True Positive"


def test_zero_callers_unchanged(tmp_path):
    p = _repo(tmp_path, functions=[_fn("verifySig")], callers=[], sources={_SIG: _DECL})
    assert _gate(p, _finding()).verdict == "True Positive"


def test_repo_wide_homonym_unchanged(tmp_path):
    p = _repo(
        tmp_path,
        functions=[_fn("verifySig"), _fn("verifySig", file="internal/legacy/old.go")],
        callers=[_cr("TestVerify", "internal/crypto/signature_test.go")],
        sources={_SIG: _DECL, "internal/legacy/old.go": _DECL},
    )
    assert _gate(p, _finding()).verdict == "True Positive"


def test_main_excluded_unchanged(tmp_path):
    decl = "package main\n\nfunc main() {\n\t_ = 1\n}\n"
    p = _repo(
        tmp_path,
        functions=[_fn("main", file="cmd/mockserver/main.go")],
        callers=[_cr("TestMain", "cmd/mockserver/main_test.go", callee="main", callee_file="cmd/mockserver/main.go")],
        sources={"cmd/mockserver/main.go": decl},
    )
    assert _gate(p, _finding(file="cmd/mockserver/main.go")).verdict == "True Positive"


# ---- neutrality: non-Go finding is never touched ----

def test_non_go_finding_unchanged(tmp_path):
    p = _repo(
        tmp_path,
        functions=[_fn("verifySig")],
        callers=[_cr("TestVerify", "internal/crypto/signature_test.go")],
        sources={_SIG: _DECL, "internal/crypto/signature_test.go": _TEST_SRC},
    )
    assert _gate(p, _finding(lang="php", cwes=("CWE-89",))).verdict == "True Positive"


# ---- projection soundness: abs/rel duplicate paths resolve to the same symbol ----

def test_path_normalization_is_stable(tmp_path):
    p = _repo(tmp_path, functions=[_fn("verifySig")], sources={_SIG: _DECL})
    a = p.resolve_repo_unique_enclosing_function("svc", "go", _SIG, 4)
    b = p.resolve_repo_unique_enclosing_function("svc", "go", "./" + _SIG, 4)
    assert a.symbol is not None and b.symbol is not None
    assert a.symbol.source_ref.file == b.symbol.source_ref.file == _SIG


# ---- #162 residual: the same end-to-end path for non-Go languages ----
#
# The unit tests in test_p5b_reachability_gate.py script the provider, so they
# never exercise the real per-language declaration-token location or extension-
# bounded scan. These drive the REAL ContextProvider for each newly supported
# language, which is what proves the generalization actually works on source.

_PY_DECL = "def verify_sig(a, b):\n    return a == b\n"
_PY_TEST = "from app.crypto.signature import verify_sig\n\n\ndef test_v():\n    verify_sig('a', 'b')\n"
_TS_DECL = "export function verifySig(a: string, b: string): boolean {\n  return a === b;\n}\n"
_TS_TEST = "import { verifySig } from './signature';\n\nit('v', () => { verifySig('a', 'b'); });\n"
_PHP_DECL = "<?php\nfunction verifySig($a, $b) {\n    return $a == $b;\n}\n"
_PHP_TEST = "<?php\nclass SignatureTest {\n    public function testV() { verifySig('a','b'); }\n}\n"


def _lang_repo(tmp_path, *, lang, decl_file, decl_src, test_file, test_src, fn, sink_line):
    """Build a real repo + context CSVs for *lang* with one test-only function."""
    return _repo(
        tmp_path,
        functions=[{
            "name": fn, "file": decl_file,
            "start_line": str(sink_line - 1), "end_line": str(sink_line + 1),
        }],
        callers=[{
            "callee_name": fn, "callee_file": decl_file, "caller_name": "test_v",
            "caller_file": test_file, "caller_start_line": "1", "caller_end_line": "5",
        }],
        sources={decl_file: decl_src, test_file: test_src},
        lang=lang,
    )


def _lang_finding(lang, file, line):
    return Finding(
        rule_id=f"{lang}/timing-unsafe-comparison", message="timing", file=file,
        start_line=line, end_line=line, repo_name="svc", lang=lang, cwe_ids=["CWE-208"],
    )


def test_python_test_only_function_downgrades(tmp_path):
    p = _lang_repo(
        tmp_path, lang="python",
        decl_file="app/crypto/signature.py", decl_src=_PY_DECL,
        test_file="app/crypto/test_signature.py", test_src=_PY_TEST,
        fn="verify_sig", sink_line=2,
    )
    f = _lang_finding("python", "app/crypto/signature.py", 2)
    v = Verdict(
        finding=f, verdict="True Positive", confidence="High", reasoning="==",
        answers=[], raw_response="{}", model="m", confidence_score=0.9,
    )
    out = _downgrade_test_only_reachability(v, f, p, 2)
    assert out.verdict == "Needs More Data"
    assert out.decision_source == "reachability_gate"


def test_typescript_test_only_function_downgrades(tmp_path):
    p = _lang_repo(
        tmp_path, lang="javascript",
        decl_file="src/crypto/signature.ts", decl_src=_TS_DECL,
        test_file="src/crypto/signature.test.ts", test_src=_TS_TEST,
        fn="verifySig", sink_line=2,
    )
    f = _lang_finding("javascript", "src/crypto/signature.ts", 2)
    v = Verdict(
        finding=f, verdict="True Positive", confidence="High", reasoning="===",
        answers=[], raw_response="{}", model="m", confidence_score=0.9,
    )
    out = _downgrade_test_only_reachability(v, f, p, 2)
    assert out.verdict == "Needs More Data"
    assert out.decision_source == "reachability_gate"


def test_php_test_only_function_downgrades(tmp_path):
    p = _lang_repo(
        tmp_path, lang="php",
        decl_file="src/Crypto/Signature.php", decl_src=_PHP_DECL,
        test_file="tests/Crypto/SignatureTest.php", test_src=_PHP_TEST,
        fn="verifySig", sink_line=3,
    )
    f = _lang_finding("php", "src/Crypto/Signature.php", 3)
    v = Verdict(
        finding=f, verdict="True Positive", confidence="High", reasoning="==",
        answers=[], raw_response="{}", model="m", confidence_score=0.9,
    )
    out = _downgrade_test_only_reachability(v, f, p, 3)
    assert out.verdict == "Needs More Data"
    assert out.decision_source == "reachability_gate"


def test_python_production_reference_vetoes(tmp_path):
    """A real non-test .py file referencing the function keeps the TP standing.

    Exercises the negative veto through the real extension-bounded scan.
    """
    p = _lang_repo(
        tmp_path, lang="python",
        decl_file="app/crypto/signature.py", decl_src=_PY_DECL,
        test_file="app/crypto/test_signature.py", test_src=_PY_TEST,
        fn="verify_sig", sink_line=2,
    )
    (tmp_path / "repos" / "python" / "svc" / "app" / "api").mkdir(parents=True, exist_ok=True)
    (tmp_path / "repos" / "python" / "svc" / "app" / "api" / "handler.py").write_text(
        "from app.crypto.signature import verify_sig\n\nverify_sig('a','b')\n", encoding="utf-8"
    )
    f = _lang_finding("python", "app/crypto/signature.py", 2)
    v = Verdict(
        finding=f, verdict="True Positive", confidence="High", reasoning="==",
        answers=[], raw_response="{}", model="m", confidence_score=0.9,
    )
    assert _downgrade_test_only_reachability(v, f, p, 2).verdict == "True Positive"


def test_unsupported_language_abstains_end_to_end(tmp_path):
    """A Java finding with identical test-only evidence stays a True Positive."""
    p = _lang_repo(
        tmp_path, lang="java",
        decl_file="src/main/java/Sig.java",
        decl_src="class Sig {\n  boolean verifySig(String a, String b) {\n    return a == b;\n  }\n}\n",
        test_file="src/test/java/SigTest.java",
        test_src="class SigTest { void t() { new Sig().verifySig(\"a\",\"b\"); } }\n",
        fn="verifySig", sink_line=3,
    )
    f = _lang_finding("java", "src/main/java/Sig.java", 3)
    v = Verdict(
        finding=f, verdict="True Positive", confidence="High", reasoning="==",
        answers=[], raw_response="{}", model="m", confidence_score=0.9,
    )
    assert _downgrade_test_only_reachability(v, f, p, 3).verdict == "True Positive"
