# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Documentation-drift guards for README.md and config/RULES.md.

Every rule/question count in the docs had silently rotted out of sync with the
files on disk (README claimed 394 guided questions against an actual 399, 64
CodeQL queries against 65, 103 Semgrep rules against 108, and omitted the C#
question bank entirely). These tests pin each documented number to the tree so
adding a rule without documenting it fails CI instead of quietly ageing the docs.

Each test derives the expected value from the source of truth, so the fix for a
failure is to update the doc, never to update the test.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
README = REPO_ROOT / "README.md"
RULES_MD = REPO_ROOT / "config" / "RULES.md"
PROMPTS_DIR = REPO_ROOT / "config" / "prompts"
CODEQL_DIR = REPO_ROOT / "config" / "codeql-custom"
SEMGREP_DIR = REPO_ROOT / "config" / "semgrep-custom"


def _documented_number(text: str, pattern: str) -> int:
    """Extract the single integer captured by ``pattern``, or fail loudly."""
    match = re.search(pattern, text)
    assert match is not None, f"doc pattern not found — did the wording change? {pattern!r}"
    return int(match.group(1))


def _question_bank_sizes() -> dict[str, int]:
    """Rule-set count per guided-question bank, keyed by file name."""
    sizes: dict[str, int] = {}
    for path in sorted(PROMPTS_DIR.glob("*_questions.yaml")):
        data = yaml.safe_load(path.read_text()) or {}
        # Banks are either {questions: {...}} or a bare top-level mapping.
        questions = data.get("questions", data)
        sizes[path.name] = len(questions)
    return sizes


def _codeql_counts() -> dict[str, int]:
    """Custom CodeQL query count per language directory."""
    return {
        lang_dir.name: len(list((lang_dir / "src").glob("*.ql")))
        for lang_dir in sorted(CODEQL_DIR.iterdir())
        if (lang_dir / "src").is_dir()
    }


def _semgrep_rules() -> dict[str, list[dict]]:
    """Custom Semgrep rules per language file."""
    return {
        path.stem: (yaml.safe_load(path.read_text()) or {}).get("rules", [])
        for path in sorted(SEMGREP_DIR.glob("*.yaml"))
    }


# ── Guided-question banks ───────────────────────────────────────────────────


def test_readme_guided_question_total_matches_banks():
    """Both README totals must equal the sum of the per-language banks.

    The fallback bank (default_questions.yaml) is counted separately in the
    docs as "+ 1 fallback", so it is excluded from the total here.
    """
    sizes = _question_bank_sizes()
    expected = sum(n for name, n in sizes.items() if name != "default_questions.yaml")
    readme = README.read_text()

    assert _documented_number(readme, r"(\d+) rule-specific templates") == expected
    assert (
        _documented_number(readme, r"Guided-question templates \| (\d+) across") == expected
    )


@pytest.mark.parametrize("bank", sorted(_question_bank_sizes()))
def test_readme_documents_each_question_bank(bank: str):
    """Every bank on disk needs a README row carrying its real count.

    Guards the specific gap found in the audit: cs_questions.yaml (C#, 45 rule
    sets) shipped without any README row at all.
    """
    expected = _question_bank_sizes()[bank]
    documented = _documented_number(
        README.read_text(), rf"`{re.escape(bank)}` \| [^|]+ \| (\d+) \|"
    )
    assert documented == expected, f"{bank}: README says {documented}, tree has {expected}"


# ── Custom CodeQL queries ───────────────────────────────────────────────────


def test_readme_custom_codeql_total():
    counts = _codeql_counts()
    documented = _documented_number(README.read_text(), r"Custom CodeQL queries \| (\d+) \(")
    assert documented == sum(counts.values())


@pytest.mark.parametrize("lang", sorted(_codeql_counts()))
def test_rules_md_codeql_section_count(lang: str):
    documented = _documented_number(
        RULES_MD.read_text(), rf"codeql-custom/{lang}/src/\)\s*\((\d+) rules\)"
    )
    assert documented == _codeql_counts()[lang]


@pytest.mark.parametrize("lang", sorted(_codeql_counts()))
def test_every_codeql_query_is_documented(lang: str):
    """Each .ql file's @id must appear in RULES.md.

    Catches the py/jinja-autoescape-disabled case: a query that shipped and was
    wired into a profile but never made it into the inventory.
    """
    rules_md = RULES_MD.read_text()
    undocumented = []
    for query in sorted((CODEQL_DIR / lang / "src").glob("*.ql")):
        match = re.search(r"@id\s+([a-z0-9/_-]+)", query.read_text())
        assert match, f"{query} has no @id"
        if f"`{match.group(1)}`" not in rules_md:
            undocumented.append(match.group(1))
    assert not undocumented, f"undocumented in RULES.md: {undocumented}"


# ── Custom Semgrep rules ────────────────────────────────────────────────────


def test_readme_custom_semgrep_total():
    documented = _documented_number(README.read_text(), r"Custom Semgrep rules \| (\d+) \(")
    assert documented == sum(len(r) for r in _semgrep_rules().values())


@pytest.mark.parametrize("lang", sorted(_semgrep_rules()))
def test_rules_md_semgrep_section_count(lang: str):
    documented = _documented_number(
        RULES_MD.read_text(), rf"semgrep-custom/{lang}\.yaml\)\s*\((\d+) rules\)"
    )
    assert documented == len(_semgrep_rules()[lang])


@pytest.mark.parametrize("lang", sorted(_semgrep_rules()))
def test_every_semgrep_rule_is_documented(lang: str):
    """Each Semgrep rule id must appear in RULES.md."""
    rules_md = RULES_MD.read_text()
    undocumented = [
        rule["id"] for rule in _semgrep_rules()[lang] if rule.get("id", "") not in rules_md
    ]
    assert not undocumented, f"undocumented in RULES.md: {undocumented}"
