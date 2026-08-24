# VulnHunterX: making SAST findings worth reading

*A static-analysis triage pipeline that answers a checklist before it answers "is this real?" — and the benchmark numbers that came out of it.*

---

## The problem is not detection

Run CodeQL's `security-and-quality` suite against a mid-sized web application and you will get hundreds of findings. Run Semgrep's registry packs alongside it and you will get hundreds more. Almost none of that output is wrong, exactly — SAST engines are built to over-approximate. They flag every program point that *might* be reachable with attacker-controlled data, because the alternative is silently dropping real bugs.

The cost of that design decision does not land on the analysis. It lands on a human, reading alert #212 of 400, deciding for the fourth time that day whether `escapeshellarg()` two frames up actually neutralizes the sink.

That is the job VulnHunterX automates. It is not another detector. It sits *behind* the detectors, takes their SARIF, and decides which findings a human should actually spend time on.

On our in-repo ground-truth suite, treating every SAST finding as real gives **70% precision**. After verification: **92% precision at 95% recall**. On OWASP BenchmarkPython, raw SAST scores 37.7% precision; verification takes it to **87.3% at 98.2% recall** — a 91.4% reduction in false positives while losing under 2% of the true ones.

Here is how it works, and here is where it doesn't.

---

## The method: answer the checklist, then commit

VulnHunterX implements the [Vulnhalla methodology](https://www.cyberark.com/resources/threat-research-blog/vulnhalla-picking-the-true-vulnerabilities-from-the-codeql-haystack) — guided-question, evidence-anchored triage. The core idea is that asking an LLM "is this SQL injection real?" produces a confident coin flip, while forcing it to answer a rule-specific checklist *before* it is allowed to emit a verdict produces something you can audit.

Three mechanisms do the work:

**1. Rule-specific guided questions.** Each SARIF `ruleId` routes to a question bank — 394 templates across seven per-language banks. A `cpp/use-after-free` finding gets asked about the free site, the lifetime of the pointer, and whether the deref is conditionally guarded. A `php/tainted-filename` finding gets asked about the source superglobal, every intermediate transformation, and whether the sink is protected by a whitelist or merely by a key check. Routing is three-tier: exact `ruleId` match → normalized/prefix match → CWE map (124 entries), falling back to generic questions only when nothing hits.

**2. Answers before verdict.** The model must produce the answer sheet first. Here is a real one, from a `tainted-filename` finding in DVWA:

> - *"The potentially dangerous data originates from the `$_GET['doc']` superglobal, which is user input (line 26)."*
> - *"The data flows through `$selectedDocId` (line 27), then into `$readFile` via `$docs[$selectedDocId]['file']` (line 31)."*
> - *"There is a check using `array_key_exists()` to ensure that `$selectedDocId` exists in the `$docs` array (line 28-29). However, this only restricts the key to those defined in `$docs`, not the actual file path."*

Whether or not you agree with the conclusion the model drew from that (we'll come back to this exact finding — it's instructive), you can *check* it. Each claim names a line. A verdict with no answer sheet is unfalsifiable; a verdict with one is reviewable in thirty seconds.

**3. Multi-turn context expansion.** A snippet is rarely enough. The model can request more — callers, structs, globals, macros, free-sites, destructors, field-writes — from a fixed vocabulary, and the engine serves it from CSVs pre-extracted by CodeQL (or tree-sitter, when no database could be built). It reasons across up to `max_iterations` rounds rather than pattern-matching a single window. On our ground-truth suite the mean is 2.49 rounds per finding.

The output is a structured verdict — `TRUE_POSITIVE` / `FALSE_POSITIVE` / `NEEDS_MORE_DATA` — with a confidence level and the full reasoning trace.

---

## The pipeline

```
Source ──> Static Analysis ──> SARIF ──> LLM Verification ──> Verdicts ──> Fuzz confirmation
(prepare)  (CodeQL/Semgrep/   (rule,     (guided questions,   (TP/FP/NMD   (libFuzzer/Atheris/
            OpenGrep)          file,      multi-turn)          + conf.)     Jazzer harnesses)
                               line)
```

Eight stages, of which the first four are the core loop:

| # | Command | Output |
|---|---|---|
| 1 | `prepare` | Source + CodeQL DB + context CSVs |
| 2 | `analyze` | SARIF findings |
| 3 | `verify` | JSON verdicts + reasoning |
| 4 | `report` | Markdown report (EN/VI) |
| 5–8 | `build-sanitized` → `fuzz-run` | ASan/UBSan build, generated harnesses, crash triage |

Stages 5–8 are the escalation path: for findings the verifier confirms, generate a fuzzing harness and try to actually crash the thing. Harness generation covers C/C++ (libFuzzer), Python (Atheris), Java (Jazzer), JavaScript (Jazzer.js), and PHP (php-fuzzer), with an LLM-driven repair loop for harnesses that fail to compile.

**Coverage:** C, C++, Python, JavaScript, PHP, Java, Go, C#. Three engines (CodeQL, Semgrep, OpenGrep). Five rule profiles from `standard` to `full`, where `full` layers 64 custom CodeQL queries and 103 custom Semgrep rules on top of the built-in suites — roughly 5–10× more rules per scan than the default. Any LLM provider LiteLLM speaks: OpenAI, Anthropic, Gemini, DeepSeek, or local/cloud Ollama.

```bash
vuln-hunter-x scan --url https://github.com/org/app.git --lang python --profile full --limit 10
```

---

## Results, part 1: the regression suite

We maintain a version-A/B harness (`benchmark/`) that scores the verifier against four deliberately-vulnerable targets with hand-built ground truth: **dvcp** (C), **dvwa** (PHP), **insecure-coding-examples** (C/C++), and **nodegoat** (JavaScript). 125 findings total — 88 genuinely real, 37 not real. Every run is scored against the same labels, and every commit that touches the verifier gets re-scored against the previous baseline.

Latest run (`gpt-5.5`, temperature 0):

| | Precision | Recall |
|---|---|---|
| Raw SAST (every finding is real) | 70% | 100% |
| **VulnHunterX** | **92%** | **95%** |

Per target:

| Target | Language | Precision | Recall | Findings |
|---|---|---|---|---|
| dvcp | C | 100% | 100% | 5 |
| dvwa | PHP | 89% | 100% | 72 |
| insecure-coding-examples | C/C++ | 92% | 88% | 32 |
| nodegoat | JavaScript | 100% | 94% | 17 |

Cost for the full 125-finding suite: **$14.58**, or about **$0.12 per finding**, at 69% prompt-cache hit rate. One abstention (`NEEDS_MORE_DATA`), zero errors.

### The part that took seven iterations

The suite exists because the first version was not good. Here is every scored baseline, in order:

| Date | Commit | Precision | Recall | What changed |
|---|---|---|---|---|
| Jul 01 | `eda2fd0` | 83% | 81% | first scored baseline |
| Jul 03 | `795e4fd` | 84% | 86% | |
| Jul 08 | `8a63259` | 84% | 88% | |
| Jul 09 | `b83c870` | **93%** | 89% | impact-first verdict; fixed over-confirmation and CWE tunnel-vision |
| Jul 11 | `b99ed57` | **94%** | 88% | buffer-overflow family cross-rule reconciliation |
| Jul 11 | `182d98e` | 92% | **97%** | sibling-consistency re-verification |
| Jul 12 | `28eab8b` | 92% | **95%** | verifier reads the scanner's taint source to resolve reachability |

Precision moved first, then recall — and the two traded against each other repeatedly. The jump from `eda2fd0` to the current head is **+10 points of precision and +15 of recall**, but it took 32 individual verdict flips, of which **six were regressions**. The harness reports those flips explicitly, which is the only reason we caught, for example, that hardening the reachability logic broke three `if_constexpr.cpp` cases that had been passing.

Costs fell alongside: **-$2.47** per suite run, -104k input tokens, -53k output tokens, +8.5pp cache hit rate, and mean iterations down from 2.90 to 2.49. Better reasoning turned out to be cheaper reasoning — the model stopped asking for context it didn't need.

### An honest example

Earlier we quoted the answer sheet for a `tainted-filename` finding in DVWA's `instructions.php:26`. That run — a weaker model, one iteration, no context expansion — concluded **True Positive** with High confidence.

The ground truth says it is **not real**. The current verifier calls it a False Positive, correctly.

The answer sheet was not wrong about the facts. It correctly identified the source, the flow, and the `array_key_exists()` check. It then reasoned that the check "only restricts the key, not the actual file path" — technically true, and irrelevant, because the values in `$docs` are hardcoded literals. A single-pass model with a 40-line window could not see that. A model that requests the array definition can.

That gap — between correct facts and a correct conclusion — is most of what the seven iterations above were fixing.

---

## Results, part 2: public datasets

The `benchmarks/` framework scores the pipeline against public ground-truth corpora, comparing four approaches: `raw-sast` (no LLM, upper-bound recall), `vulnhunterx` (full pipeline), `ablation-generic` (same pipeline, generic questions only), and `ablation-zero` (same pipeline, no questions).

**OWASP BenchmarkPython** (300 cases):

| Approach | Model | Precision | Recall | F1 | FP-reduction |
|---|---|---|---|---|---|
| raw-sast | — | 37.7% | 100% | 54.7% | 0% |
| ablation-zero | DeepSeek | 77.3% | 96.5% | 85.8% | 82.9% |
| ablation-generic | DeepSeek | 81.1% | 94.7% | 87.4% | 86.6% |
| **vulnhunterx** | **DeepSeek** | **87.3%** | **98.2%** | **92.4%** | **91.4%** |
| **vulnhunterx** | **gpt-4.1-mini** | **82.7%** | **97.4%** | **89.4%** | **87.7%** |

This is the cleanest result in the set: the full pipeline beats both ablations on precision *and* recall, for every model tested. Guided questions are doing real work.

**OWASP BenchmarkJava** (300 cases): raw SAST starts higher at 61.0% precision. `vulnhunterx` with DeepSeek reaches 87.6% / 96.7% (F1 92.0, 78.6% FP-reduction); gpt-4.1-mini reaches 78.0% / 95.1%.

**SecLLMHolmes** (handcrafted bad/good pairs, 8 CWE classes): raw SAST 52.3% precision by construction. `vulnhunterx` reaches 82.1% / 87.5% with DeepSeek, 78.4% / 85.9% with gpt-5, 74.7% / 89.9% with gpt-4.1-mini, 70.5% / 87.8% with local qwen3-coder.

**Juliet C/C++ 1.3.1**: raw SAST 50% by construction. `vulnhunterx` with DeepSeek reaches 83.8% / 93.8%.

With the strongest model tested (DeepSeek), the full pipeline reduces false positives by **78.6–91.4%** across all four datasets while retaining **87.5–98.2%** of true positives. Across every model tested, recall stays between **86% and 100%** — the pipeline rarely throws away real bugs. Precision gains vary far more, which is the subject of the next section.

---

## Where it doesn't work

Publishing only the good rows would make this a worse post.

**Model choice dominates everything.** gpt-4.1-mini on Juliet reduces false positives by 23.9% — barely better than useless — while DeepSeek on the same dataset and same pipeline reaches 82.2%. The pipeline is a force multiplier on model capability, not a substitute for it. Budget accordingly: on hard memory-safety reasoning, a cheap model plus good scaffolding still loses to a good model.

**Guided questions do not always help.** On Juliet, `ablation-generic` (88.1% / 98.9%) *beat* the full guided-question pipeline (83.8% / 93.8%) with DeepSeek. Our read: Juliet's synthetic `bad()`/`good()` function pairs are self-contained by construction, so rule-specific questions add prompt length without adding signal — and occasionally talk the model into over-thinking a two-line case. Guided questions earn their keep on real code with real distance between source and sink; on paired synthetic fixtures they don't.

**Some model/dataset combinations produce nothing scoreable.** Two local Ollama runs on OWASP BenchmarkJava abstained on effectively every finding — reported as 100% "FP-reduction" with no computable precision or recall, which is a failure mode wearing a success metric's clothes. One GLM run failed outright. These rows are in the published comparison tables rather than quietly dropped.

**Detection-track datasets are excluded from the headline.** DiverseVul (349K function-level labels) measures recall and TP-preservation, not FP-reduction: there is no real SAST alert behind each label, `target=0` does not mean "SAST false positive", and label accuracy is roughly 60%. Reporting it next to alert-level precision would be comparing different quantities.

**Absence-of-control bugs are out of reach.** Missing authorization, disabled CSRF middleware, absent rate limiting — SAST doesn't reliably flag them, so there is nothing for the verifier to verify. Reports carry an explicit coverage-limitations caveat for exactly this reason.

---

## Try it

```bash
git clone https://github.com/vinsoc-cyber/VulnHunterX.git && cd VulnHunterX
uv venv --python python3.12 .venv && source .venv/bin/activate
uv pip install -e ".[dev]"

cp env.example .env        # add your provider key
vuln-hunter-x check-env    # verify the toolchain

vuln-hunter-x interactive  # guided wizard, no flags to remember
```

Or run one of the per-language example scripts, each of which scans a real-world project *and* a deliberately-vulnerable one so the true-positive/false-positive contrast is visible in a single report:

```bash
python examples/pipeline_python.py    # pyyaml (real) vs dvpwa (vulnerable)
python examples/pipeline_c.py --fuzz  # c-ares vs dvcp, with fuzz confirmation
```

Reproduce the benchmarks:

```bash
python benchmarks/scripts/setup_datasets.py --dataset owasp-python
python benchmarks/scripts/run_benchmark.py --dataset owasp-python --approach all --model gpt-4.1-mini
python benchmark/src/benchmark.py versionab   # the 125-finding regression suite
```

MIT licensed. Rule inventory in [`config/RULES.md`](../../config/RULES.md), benchmark methodology and literature review in [`benchmarks/RESEARCH.md`](../../benchmarks/RESEARCH.md), ground-truth catalogues in [`docs/benchmarks/ground-truth-baselines.md`](../benchmarks/ground-truth-baselines.md).

---

*Benchmark figures: version-A/B suite run 2026-07-12 on `gpt-5.5` at temperature 0; public-dataset matrices run 2026-05-31 through 2026-06-05. All result files are committed under `benchmark/result/` and `benchmarks/results/`.*
