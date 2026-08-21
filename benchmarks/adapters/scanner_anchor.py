# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Scanner-derived sink-line anchoring for function-granularity datasets (#125).

Function-granularity adapters (SecLLMHolmes, Juliet, …) label whole files or
functions and therefore cannot set ``GroundTruthEntry.sink_line``. Since #125
the line-aware verifier approaches exclude such entries, which silently reduced
"LLM benchmarks" on those datasets to zero LLM calls.

This module restores real LLM benchmarking by producing *genuine* anchors: it
runs OpenGrep (the product's own offline scanner, vendored rules under
``config/opengrep-rules/<lang>``) over the dataset files and anchors each entry
on an actual scanner finding in its file. Entries the scanner never flags stay
unanchored and are dropped — loudly — because the product verifier only ever
sees scanner findings; that is the population the benchmark measures.

Alignment policy (``alignment=``):
    strict  — anchor only on findings whose rule carries the entry's CWE tag.
              A CWE-676 "dangerous function" hit inside a CWE-22 scenario is
              NOT an anchor: a correct verdict about the strcpy would be scored
              against the path-traversal label (see
              benchmarks/results/secllmholmes_anchored/REPORT.md §"Rule-alignment").
    any     — anchor on any scanner finding in the entry's file, preferring
              CWE-aligned ones. Marks each entry with
              ``metadata["rule_aligned"]`` so reports can slice by alignment.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from benchmarks.adapters.ground_truth import GroundTruthEntry

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_RULES_ROOT = _REPO_ROOT / "config" / "opengrep-rules"

# Adapter language label → vendored offline rules directory name
_LANG_RULE_DIRS: dict[str, str] = {
    "c": "c",
    "cpp": "cpp",
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "php": "php",
    "java": "java",
    "go": "go",
}

_CACHE_VERSION = 1
_CACHE_FILENAME = ".vhx_anchor_cache.json"
# Max file targets per opengrep invocation (stay far below ARG_MAX)
_CHUNK = 400


@dataclass
class AnchorStats:
    """Outcome of one :func:`anchor_entries` pass, for loud reporting."""

    total: int = 0
    pre_anchored: int = 0          # entries that already had a real sink_line
    anchored_aligned: int = 0      # anchored on a CWE-aligned finding
    anchored_misaligned: int = 0   # anchored on an unaligned finding (alignment="any")
    dropped_no_finding: int = 0    # scanner produced nothing in the entry's file
    dropped_misaligned: int = 0    # findings existed but none CWE-aligned (strict)
    dropped_unscannable: int = 0   # file missing on disk or language has no rules
    scanned_files: int = 0
    cache_hit: bool = False
    by_label: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def anchored(self) -> int:
        return self.pre_anchored + self.anchored_aligned + self.anchored_misaligned

    @property
    def dropped(self) -> int:
        return self.dropped_no_finding + self.dropped_misaligned + self.dropped_unscannable

    def count(self, label: str, outcome: str) -> None:
        self.by_label.setdefault(label, {})[outcome] = (
            self.by_label.get(label, {}).get(outcome, 0) + 1
        )

    def summary(self) -> str:
        parts = [
            f"{self.anchored}/{self.total} entries anchored on real scanner findings",
            f"{self.dropped_no_finding} dropped (no scanner finding in file)",
        ]
        if self.dropped_misaligned:
            parts.append(
                f"{self.dropped_misaligned} dropped (findings present but none "
                "match the entry's CWE; use --anchor-alignment any to keep them)"
            )
        if self.dropped_unscannable:
            parts.append(f"{self.dropped_unscannable} dropped (file missing or no rules for language)")
        if self.anchored_misaligned:
            parts.append(f"{self.anchored_misaligned} anchored on rule-MISALIGNED findings")
        label_bits = ", ".join(
            f"{lbl}: " + "/".join(f"{k}={v}" for k, v in sorted(cnts.items()))
            for lbl, cnts in sorted(self.by_label.items())
        )
        if label_bits:
            parts.append(f"per-label [{label_bits}]")
        return "; ".join(parts)


def opengrep_binary() -> str | None:
    """Resolve the OpenGrep binary the product itself would use, or None."""
    binary = os.environ.get("OPENGREP_PATH", "opengrep")
    return binary if shutil.which(binary) else None


def _rules_fingerprint(langs: set[str]) -> str:
    h = hashlib.sha256()
    for lang in sorted(langs):
        rules_dir = _RULES_ROOT / _LANG_RULE_DIRS[lang]
        for p in sorted(rules_dir.rglob("*.yaml")):
            st = p.stat()
            h.update(f"{p.relative_to(_RULES_ROOT)}|{st.st_mtime_ns}|{st.st_size}\n".encode())
    return h.hexdigest()


def _targets_fingerprint(dataset_root: Path, rel_files: set[str]) -> str:
    h = hashlib.sha256()
    for rel in sorted(rel_files):
        st = (dataset_root / rel).stat()
        h.update(f"{rel}|{st.st_mtime_ns}|{st.st_size}\n".encode())
    return h.hexdigest()


def _run_opengrep(
    binary: str, dataset_root: Path, rel_files: list[str], lang: str
) -> list[dict]:
    """Run OpenGrep over ``rel_files`` (relative to ``dataset_root``).

    Returns finding dicts: ``{"file", "line", "rule_id", "message", "cwes"}``.
    Runs with ``cwd=dataset_root`` and relative targets so SARIF URIs match
    ``GroundTruthEntry.file_path`` without path juggling.
    """
    from vuln_hunter_x.sarif.parser import SarifParser

    rules_dir = _RULES_ROOT / _LANG_RULE_DIRS[lang]
    findings: list[dict] = []

    for i in range(0, len(rel_files), _CHUNK):
        chunk = rel_files[i : i + _CHUNK]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sarif", prefix=f"vhx_anchor_{lang}_", delete=False
        ) as tf:
            sarif_path = Path(tf.name)
        try:
            argv = [
                binary,
                "scan",
                "--sarif",
                f"--sarif-output={sarif_path}",
                "--config",
                str(rules_dir),
                *chunk,
            ]
            logger.info(
                "anchor: %s over %d %s file(s) (rules: %s)",
                binary, len(chunk), lang, rules_dir,
            )
            result = subprocess.run(  # noqa: S603 — fixed argv, no shell
                argv,
                cwd=dataset_root,
                capture_output=True,
                text=True,
                timeout=1800,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"opengrep failed (exit {result.returncode}) anchoring {lang} "
                    f"files: {(result.stderr or result.stdout).strip()[-500:]}"
                )
            for f in SarifParser(sarif_path).parse_findings(lang=lang, repo_name="anchor"):
                if not f.file or not f.start_line:
                    continue
                findings.append(
                    {
                        "file": str(Path(f.file)),  # normalize separators
                        "line": f.start_line,
                        "rule_id": f.rule_id,
                        "message": f.message,
                        "cwes": list(f.cwe_ids or []),
                    }
                )
        finally:
            sarif_path.unlink(missing_ok=True)

    return findings


def _load_findings(
    binary: str,
    dataset_root: Path,
    files_by_lang: dict[str, list[str]],
    use_cache: bool,
    stats: AnchorStats,
) -> dict[str, list[dict]]:
    """Scan (or load cached) findings, keyed by dataset-relative file path."""
    all_rel = {rel for rels in files_by_lang.values() for rel in rels}
    fingerprint = (
        f"v{_CACHE_VERSION}|"
        + _targets_fingerprint(dataset_root, all_rel)
        + "|"
        + _rules_fingerprint(set(files_by_lang))
    )
    cache_path = dataset_root / _CACHE_FILENAME

    if use_cache and cache_path.is_file():
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            if cached.get("fingerprint") == fingerprint:
                logger.info("anchor: using cached scanner findings (%s)", cache_path)
                stats.cache_hit = True
                return cached["findings_by_file"]
        except (json.JSONDecodeError, OSError, KeyError):
            logger.warning("anchor: ignoring unreadable cache %s", cache_path)

    findings_by_file: dict[str, list[dict]] = {}
    for lang, rel_files in sorted(files_by_lang.items()):
        for f in _run_opengrep(binary, dataset_root, sorted(rel_files), lang):
            findings_by_file.setdefault(f["file"], []).append(f)
    for flist in findings_by_file.values():
        flist.sort(key=lambda f: (f["line"], f["rule_id"]))

    if use_cache:
        try:
            cache_path.write_text(
                json.dumps(
                    {"fingerprint": fingerprint, "findings_by_file": findings_by_file}
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("anchor: cannot write cache %s: %s", cache_path, exc)

    return findings_by_file


def anchor_entries(
    entries: list[GroundTruthEntry],
    dataset_root: Path,
    alignment: str = "strict",
    binary: str | None = None,
    use_cache: bool = True,
) -> tuple[list[GroundTruthEntry], AnchorStats]:
    """Anchor line-unanchored entries on real OpenGrep findings.

    Returns ``(anchored_entries, stats)`` where ``anchored_entries`` contains
    only entries carrying a real scanner-derived ``sink_line`` (pre-anchored
    entries pass through untouched). Unanchored entries are dropped from the
    returned list — the benchmark population becomes "entries the scanner
    flags", which is the product verifier's actual operating domain.

    Raises FileNotFoundError when no OpenGrep binary is available and
    ValueError for an unknown ``alignment``.
    """
    if alignment not in ("strict", "any"):
        raise ValueError(f"alignment must be 'strict' or 'any', got {alignment!r}")
    binary = binary or opengrep_binary()
    if binary is None:
        raise FileNotFoundError(
            "opengrep not found (set OPENGREP_PATH or install opengrep); "
            "cannot derive real sink-line anchors"
        )

    dataset_root = Path(dataset_root)
    stats = AnchorStats(total=len(entries))

    # Collect scannable files for the entries that actually need an anchor.
    files_by_lang: dict[str, set[str]] = {}
    for e in entries:
        if e.is_line_anchored:
            continue
        if e.lang not in _LANG_RULE_DIRS or not (dataset_root / e.file_path).is_file():
            continue
        files_by_lang.setdefault(e.lang, set()).add(e.file_path)

    findings_by_file: dict[str, list[dict]] = {}
    if files_by_lang:
        findings_by_file = _load_findings(
            binary,
            dataset_root,
            {lang: sorted(rels) for lang, rels in files_by_lang.items()},
            use_cache,
            stats,
        )
        stats.scanned_files = sum(len(v) for v in files_by_lang.values())

    kept: list[GroundTruthEntry] = []
    for e in entries:
        if e.is_line_anchored:
            stats.pre_anchored += 1
            stats.count(e.label, "pre_anchored")
            kept.append(e)
            continue

        if e.lang not in _LANG_RULE_DIRS or not (dataset_root / e.file_path).is_file():
            stats.dropped_unscannable += 1
            stats.count(e.label, "dropped")
            continue

        candidates = findings_by_file.get(str(Path(e.file_path)), [])
        aligned = [f for f in candidates if e.cwe_id in f["cwes"]]
        chosen: dict | None = None
        if aligned:
            chosen = aligned[0]
        elif candidates and alignment == "any":
            chosen = candidates[0]

        if chosen is None:
            if candidates:
                stats.dropped_misaligned += 1
            else:
                stats.dropped_no_finding += 1
            stats.count(e.label, "dropped")
            continue

        is_aligned = bool(aligned)
        e.sink_line = chosen["line"]
        e.metadata.update(
            {
                # entry_to_finding() feeds metadata["message"] to the verifier —
                # use the scanner's real claim, not a synthesized CWE blurb.
                "message": chosen["message"],
                "anchor_tool": "opengrep",
                "anchor_rule": chosen["rule_id"],
                "anchor_cwes": chosen["cwes"],
                "rule_aligned": is_aligned,
            }
        )
        if is_aligned:
            stats.anchored_aligned += 1
        else:
            stats.anchored_misaligned += 1
        stats.count(e.label, "anchored")
        kept.append(e)

    return kept, stats
