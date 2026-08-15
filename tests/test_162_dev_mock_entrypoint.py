# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""#162: a True Positive inside a standalone dev/mock entrypoint is withheld.

``cmd/mockserver/main.go`` is a real ``main`` package under a normally-named
path, so neither the ``test/`` path rule nor the test-only-caller gate sees
it — yet it is not part of any deployed service. The gate abstains (TP -> NMD,
``reachability_gate``), never dismisses, and never touches policy verdicts.
"""

from __future__ import annotations

import pytest

from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.verification.engine import (
    _REACHABILITY_GATE,
    _downgrade_dev_mock_entrypoint,
    _is_dev_mock_entrypoint_path,
)


@pytest.mark.parametrize("path", [
    "cmd/mockserver/main.go",
    "cmd/fakeapi/main.go",
    "tools/stubclient/client.go",
    "src/demo/app.py",
    "cmd/dev-tools/main.go",
    "examples/basic/run.js",
    "internal/mockdata/gen.go",
    "sandbox/play.c",
])
def test_dev_mock_paths_detected(path):
    assert _is_dev_mock_entrypoint_path(path) is True


@pytest.mark.parametrize("path", [
    "internal/crypto/signature.go",       # production code, no tokens
    "src/device/driver.c",                # 'device' != word-bounded 'dev'
    "pkg/developer/profile.go",           # 'developer' != 'dev'
    "ops/devops/deploy.go",               # 'devops' != 'dev'
    "src/contest.c",                      # _is_test_path contract neighbours
    "lib/unittest_utils.py",
    "vulnerabilities/exec/source/low.php",
    "",
])
def test_production_paths_not_detected(path):
    assert _is_dev_mock_entrypoint_path(path) is False


def _finding(file="cmd/mockserver/main.go", lang="go"):
    return Finding(
        rule_id="go/timing-unsafe-comparison", message="m", file=file,
        start_line=332, end_line=332, repo_name="svc", lang=lang,
        cwe_ids=["CWE-208"],
    )


def _verdict(verdict="True Positive", source="legacy_model", finding=None):
    return Verdict(
        finding=finding or _finding(), verdict=verdict, confidence="High",
        reasoning="token compared with ==", answers=[], raw_response="{}",
        model="m", confidence_score=0.9, decision_source=source,
    )


def test_tp_in_mock_main_withheld_to_nmd():
    v = _verdict()
    out = _downgrade_dev_mock_entrypoint(v, v.finding)
    assert out.verdict == "Needs More Data"
    assert out.confidence == "Low"
    assert out.confidence_score <= 0.3
    assert out.decision_source == _REACHABILITY_GATE
    assert "dev/mock entrypoint" in out.reasoning


def test_language_agnostic():
    f = _finding(file="tools/fakeserver/handler.py", lang="python")
    out = _downgrade_dev_mock_entrypoint(_verdict(finding=f), f)
    assert out.verdict == "Needs More Data"


def test_production_path_untouched():
    f = _finding(file="internal/crypto/signature.go")
    out = _downgrade_dev_mock_entrypoint(_verdict(finding=f), f)
    assert out.verdict == "True Positive"


def test_fp_and_nmd_untouched():
    for vt in ("False Positive", "Needs More Data"):
        v = _verdict(verdict=vt)
        out = _downgrade_dev_mock_entrypoint(v, v.finding)
        assert out.verdict == vt


def test_policy_sourced_verdict_untouched():
    v = _verdict(source="policy")
    out = _downgrade_dev_mock_entrypoint(v, v.finding)
    assert out.verdict == "True Positive"
