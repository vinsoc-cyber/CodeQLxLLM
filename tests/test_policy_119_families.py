# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""#119 residual over-confirms → two new evidence-closure families.

Deterministic panel over the declarative core (selection, entailment,
admissibility) for permissive_cors (CWE-942/346) and loose_equality (CWE-697),
keyed to the dvwa cases from the issue:

  permissive_cors
    - wildcard origin + public OpenAPI body (gen_openapi.php:6)   -> FP
    - wildcard origin + public API index (public/index.php:11)    -> FP
    - reflected origin + credentialed content                     -> TP
    - unresolved sensitivity                                      -> NMD
  loose_equality
    - md5 self-compare, both operands attacker-sent (impossible.php:46) -> FP
    - nil-impact challenge token (javascript/index.php:43)              -> FP
    - flagged line is a sha256 computation, not a compare (:57)         -> FP
    - stored-credential-hash loose compare guarding auth                -> TP
"""

from __future__ import annotations

from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.ledger import EvidenceEntry, EvidenceOrigin
from vuln_hunter_x.verification.policy.loader import load_policy_registry
from vuln_hunter_x.verification.policy.models import FP, NMD, TP
from vuln_hunter_x.verification.policy.support import is_admissible

_REG = load_policy_registry()
_CORS = _REG.resolve_family(cwe_ids=[], rule_id="php-permissive-cors", lang="php")
_EQ = _REG.resolve_family(cwe_ids=[], rule_id="md5-loose-equality", lang="php")


# ── selection ─────────────────────────────────────────────────────────

def test_families_load_and_select_by_rule_alias():
    assert _CORS is not None and _CORS.family == "permissive_cors"
    assert _EQ is not None and _EQ.family == "loose_equality"


def test_selection_by_cwe():
    assert _REG.resolve_family(
        cwe_ids=["CWE-942"], rule_id="js/cors-thing", lang="javascript"
    ).family == "permissive_cors"
    assert _REG.resolve_family(
        cwe_ids=["CWE-697"], rule_id="some/rule", lang="php"
    ).family == "loose_equality"


def test_no_overlap_with_existing_families():
    # Every bundled family's own selectors still resolve to exactly that
    # family (resolve_family raises PolicyOverlapError on any overlap).
    for policy in _REG._policies:
        lang = next(iter(sorted(policy.languages)), "")
        for cwe in sorted(policy.cwes):
            resolved = _REG.resolve_family(cwe_ids=[cwe], rule_id="", lang=lang)
            assert resolved is not None and resolved.family == policy.family


# ── permissive_cors entailment ────────────────────────────────────────

def test_cors_wildcard_on_public_body_dismisses():
    # gen_openapi.php:6 / public/index.php:11 — the exact #119 over-confirms.
    d = entail(_CORS, {
        "sink_binding": "PERMISSIVE_ORIGIN",
        "protected_read_exposed": "NOT_EXPOSED",
    })
    assert d.verdict is FP
    assert "protected_read_exposed" in (d.terminal_reason or "")


def test_cors_credentialed_exposure_confirms():
    d = entail(_CORS, {
        "sink_binding": "PERMISSIVE_ORIGIN",
        "protected_read_exposed": "EXPOSED",
    })
    assert d.verdict is TP


def test_cors_unresolved_sensitivity_is_honest_nmd():
    d = entail(_CORS, {"sink_binding": "PERMISSIVE_ORIGIN"})
    assert d.verdict is NMD
    assert "protected_read_exposed" in (d.terminal_reason or "")


def test_cors_mislocated_header_dismisses():
    d = entail(_CORS, {"sink_binding": "NOT_PERMISSIVE"})
    assert d.verdict is FP


# ── loose_equality entailment ─────────────────────────────────────────

def test_self_compare_without_secret_dismisses():
    # impossible.php:46 — both operands from the attacker's own request.
    d = entail(_EQ, {
        "sink_binding": "LOOSE_COMPARE_PRESENT",
        "secret_operand": "NO_SECRET",
        "bypass_consequence": "SECURITY_DECISION",
    })
    assert d.verdict is FP
    assert "secret_operand" in (d.terminal_reason or "")


def test_nil_impact_token_dismisses():
    # javascript/index.php:43 — nil-impact challenge token.
    d = entail(_EQ, {
        "sink_binding": "LOOSE_COMPARE_PRESENT",
        "secret_operand": "SECRET_PRESENT",
        "bypass_consequence": "NIL_IMPACT",
    })
    assert d.verdict is FP


def test_mislocated_sink_dismisses():
    # javascript/index.php:57 — the flagged line is hash('sha256', ...), not a compare.
    d = entail(_EQ, {"sink_binding": "NOT_PRESENT"})
    assert d.verdict is FP


def test_secret_guarding_auth_confirms():
    d = entail(_EQ, {
        "sink_binding": "LOOSE_COMPARE_PRESENT",
        "secret_operand": "SECRET_PRESENT",
        "bypass_consequence": "SECURITY_DECISION",
    })
    assert d.verdict is TP


def test_unresolved_consequence_is_honest_nmd():
    d = entail(_EQ, {
        "sink_binding": "LOOSE_COMPARE_PRESENT",
        "secret_operand": "SECRET_PRESENT",
    })
    assert d.verdict is NMD


# ── admissibility ─────────────────────────────────────────────────────

_LOCAL = EvidenceEntry(id="L1", origin=EvidenceOrigin.LOCAL_SLICE, summary="line 6")
_DATAFLOW = EvidenceEntry(id="D1", origin=EvidenceOrigin.SCANNER_DATAFLOW, summary="flow")


def test_local_slice_admits_the_public_body_dismissal():
    assert is_admissible(_CORS, "protected_read_exposed", "NOT_EXPOSED", [_LOCAL])
    assert is_admissible(_CORS, "sink_binding", "PERMISSIVE_ORIGIN", [_LOCAL])


def test_dataflow_admits_secret_operand_but_not_no_secret():
    assert is_admissible(_EQ, "secret_operand", "SECRET_PRESENT", [_DATAFLOW])
    # NO_SECRET is a positive local proof about BOTH operands — dataflow alone
    # does not establish it.
    assert not is_admissible(_EQ, "secret_operand", "NO_SECRET", [_DATAFLOW])


def test_uncited_values_fail_closed():
    assert not is_admissible(_CORS, "protected_read_exposed", "EXPOSED", [])
    assert not is_admissible(_EQ, "sink_binding", "LOOSE_COMPARE_PRESENT", [])
