# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""#121: cross-file route/caller resolution + the force-decision NMD guard.

An Express handler is MOUNTED, not called (`app.post('/x', h.handleUpdate)`),
so callers.csv records nothing and the verifier hedged Needs-More-Data on a
fact sitting one file away. Caller resolution now falls back to a route-
binding scan; and a force-decision may no longer dismiss a finding whose
self-reported sole blocker is an unseen caller/route.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from vuln_hunter_x.context.evidence import EvidenceStatus
from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.llm.client import LLMClient


# ── route-binding scan ────────────────────────────────────────────────

def _mk_repo(tmp_path, name="nodegoat"):
    repo = tmp_path / "repos" / "javascript" / name
    routes = repo / "app" / "routes"
    routes.mkdir(parents=True)
    (routes / "contributions.js").write_text(
        "function ContributionsHandler(db) {\n"
        "  this.handleContributionsUpdate = (req, res, next) => {\n"
        "    const roth = eval(req.body.roth);\n"
        "  };\n"
        "}\n"
        "module.exports = ContributionsHandler;\n"
    )
    (routes / "index.js").write_text(
        "const ContributionsHandler = require('./contributions');\n"
        "module.exports = function(app, db) {\n"
        "  const contributionsHandler = new ContributionsHandler(db);\n"
        "  app.get('/contributions', isLoggedIn, contributionsHandler.displayContributions);\n"
        "  app.post('/contributions', isLoggedIn, contributionsHandler.handleContributionsUpdate);\n"
        "};\n"
    )
    # noise that must be skipped
    nm = repo / "node_modules" / "lib"
    nm.mkdir(parents=True)
    (nm / "router.js").write_text(
        "app.post('/x', handleContributionsUpdate);\n"
    )
    return repo


def _provider(tmp_path) -> ContextProvider:
    out = tmp_path / "output"
    out.mkdir(exist_ok=True)
    return ContextProvider(out, tmp_path / "repos")


def test_scan_finds_mounted_route(tmp_path):
    _mk_repo(tmp_path)
    p = _provider(tmp_path)
    hits = p.scan_js_route_bindings("nodegoat", "javascript", "handleContributionsUpdate")
    assert len(hits) == 1  # node_modules copy skipped
    ref, line = hits[0]
    assert ref.file == "app/routes/index.js"
    assert ref.start == 5
    assert "app.post('/contributions'" in line


def test_scan_requires_registration_token(tmp_path):
    repo = _mk_repo(tmp_path)
    (repo / "app" / "notes.js").write_text(
        "// handleContributionsUpdate is documented here but not mounted\n"
    )
    p = _provider(tmp_path)
    hits = p.scan_js_route_bindings("nodegoat", "javascript", "handleContributionsUpdate")
    assert [ref.file for ref, _ in hits] == ["app/routes/index.js"]


def test_scan_unknown_repo_is_empty(tmp_path):
    p = _provider(tmp_path)
    assert p.scan_js_route_bindings("ghost", "javascript", "h") == []


def test_caller_resolution_falls_back_to_route_binding(tmp_path):
    _mk_repo(tmp_path)
    p = _provider(tmp_path)
    content = p._get_caller_context("nodegoat", "javascript", "handleContributionsUpdate")
    assert "Route bindings found" in content
    assert "app/routes/index.js:5" in content
    assert "attacker-controlled request" in content


def test_caller_resolution_without_binding_keeps_diagnostic(tmp_path):
    _mk_repo(tmp_path)
    p = _provider(tmp_path)
    content = p._get_caller_context("nodegoat", "javascript", "neverMounted")
    assert "No caller" in content


def test_route_binding_result_status_is_found(tmp_path):
    from vuln_hunter_x.context.evidence import EvidenceKind, EvidenceRequest

    _mk_repo(tmp_path)
    p = _provider(tmp_path)
    res = p._resolve_caller(
        EvidenceRequest(EvidenceKind.CALLER, "handleContributionsUpdate",
                        "caller:handleContributionsUpdate"),
        "nodegoat",
        "javascript",
    )
    assert res.status is EvidenceStatus.FOUND
    assert res.provenance and res.provenance[0].file == "app/routes/index.js"


# ── force-decision NMD guard ──────────────────────────────────────────

def _client() -> LLMClient:
    c = LLMClient.__new__(LLMClient)
    c.model = "gpt-4o"
    c.provider = "openai"
    c.temperature = 0.0
    c.seed = 42
    c.max_tokens = 4096
    c.request_timeout = 30
    c._key_pool = None
    c._single_key = None
    c.num_retries = 0
    c._is_ollama_cloud = False
    c._response_format_supported = True
    return c


def _force(client, envelope: dict):
    resp = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(envelope)))],
        usage=None,
    )
    client._completion = lambda kwargs: resp  # type: ignore[method-assign]
    parsed, *_ = client._force_decision_turn([], [], 0, 0.0)
    return parsed


def test_fp_with_unseen_caller_blocker_held_as_nmd():
    parsed = _force(_client(), {
        "verdict": "False Positive",
        "confidence": "Medium",
        "reasoning": "eval sink present but no route/caller visible.",
        "signals": {"sole_blocker": "unseen_caller"},
    })
    assert parsed["verdict"] == "Needs More Data"
    assert parsed["confidence"] == "Low"
    assert "force-decision guard" in parsed["reasoning"]


def test_fp_without_blocker_signal_respected():
    parsed = _force(_client(), {
        "verdict": "False Positive",
        "confidence": "High",
        "reasoning": "intval() sanitises the id before interpolation.",
        "signals": {"sole_blocker": None},
    })
    assert parsed["verdict"] == "False Positive"


def test_tp_with_blocker_signal_untouched():
    parsed = _force(_client(), {
        "verdict": "True Positive",
        "confidence": "High",
        "reasoning": "route mounted at index.js:52 reaches eval().",
        "signals": {"sole_blocker": "unseen_caller"},
    })
    assert parsed["verdict"] == "True Positive"


def test_prompt_declares_the_exception():
    assert "sole_blocker" in LLMClient._FORCE_DECISION_PROMPT
    assert "unseen" in LLMClient._FORCE_DECISION_PROMPT
