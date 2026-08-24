# Hunting the real bugs among hundreds of SAST alerts: using guided questions so an LLM can triage on its own

Scan an application and you get 400 alerts, of which maybe 30 are real bugs. The dominant cost of running SAST is not analysis time — it is the human reading alert #212, asking for the fourth time that day whether the `escapeshellarg()` two stack frames up actually neutralizes the sink.

---

**1. Introduction**

Every modern SAST engine operates by over-approximation: it flags *every* program point that attacker-controlled data *could* reach, because the alternative — silently dropping a point — means letting a real bug through. That is a correct design decision, but it pushes the entire cost onto a human.

Concrete numbers from ground-truth datasets: on OWASP BenchmarkPython, treating every SAST alert as real yields only **37.7%** precision — nearly two-thirds of the triage effort is wasted. On Juliet C/C++ 1.3.1 the figure is **50%**. On VulnHunterX's in-house regression suite of 125 findings from four deliberately-vulnerable applications, it is **70%**.

The common reaction today is to throw an alert at an LLM and ask *"is this a real vulnerability?"*. That produces a very confident answer that is essentially a coin flip, because the model does not have the facts to answer — and, more importantly, nobody can check what it reasoned from.

This article describes how VulnHunterX solves that problem: not with a stronger model, but by **forcing the model to answer a structured, per-bug-class set of questions before it is allowed to conclude** — an implementation of the *Vulnhalla* methodology.

---

**2. Why deciding an alert is real is so hard**

**2.1. A SAST alert is a fragment stripped of its context**

What SAST returns in a SARIF file is usually just: a rule id, a file path, a line number, a severity, a message, and — if you are lucky — a chain of dataflow steps from source to sink. To decide that an alert is real, however, the triager needs to know:

- **The definition of the function containing the flagged line** — which branch the line sits in, and what condition, if any, guards it (control flow).
- **Every call site of that function** — where the input actually comes from, how many entry paths exist, and which are attacker-controlled.
- **The bodies of the functions it calls** — the real sink is often two or three layers deep, and an innocuously-named helper can be exactly where a command executes.
- **Type definitions** — struct, class, typedef, enum. A buffer's size lives in the struct definition, not on the flagged line.
- **Global and macro declarations** — a single `#define MAX_LEN 64` can be the entire answer to a buffer-overflow alert.
- **The pointer's lifetime** — for use-after-free you need *every* `free()`/`delete`/destructor site across the whole repo, not just the nearest one.
- **The dataflow** — source, the intermediate transforms, and the sink; plus the question of whether each transform is a legitimate sanitizer.

A 40-line window around the flagged line — what most "LLM triage" tools drop into the prompt — almost never contains all of the above.

**2.2. When the model is right about the facts but wrong about the verdict**

Here is a real `php/tainted-filename` alert, at `instructions.php:26` in DVWA. A weak model, one pass, no ability to request more context, answered as follows (verbatim, as produced by the model):

> - *"The potentially dangerous data originates from the `$_GET['doc']` superglobal, which is user input (line 26)."*
> - *"The data flows through `$selectedDocId` (line 27), then into `$readFile` via `$docs[$selectedDocId]['file']` (line 31)."*
> - *"There is a check using `array_key_exists()` to ensure that `$selectedDocId` exists in the `$docs` array (line 28-29). However, this only restricts the key to those defined in `$docs`, not the actual file path."*

Its verdict: **True Positive**, high confidence. Ground truth: **not a bug**.

The remarkable thing is that the model was **wrong about nothing factual**. It correctly identified the source, the flow, and the nature of the check. It only erred at the final step: `array_key_exists()` does restrict the key — but that is harmless, because every value in the `$docs` array is a hardcoded literal. The decisive information lives in the **definition of the `$docs` array**, which never appears in the 40-line window.

The gap between "right about the facts" and "right about the verdict" is exactly the gap a verification system must close — and it is closed not by switching to a more expensive model, but by **letting the model request the precise fragment of context it is missing**.

---

**3. The architecture of VulnHunterX**

VulnHunterX is not a new detector. It sits *behind* the detectors, takes their SARIF, and decides which alerts a human should actually spend time on.

```
Source  ──>  Static Analysis  ──>  SARIF  ──>  LLM Verification  ──>  Verdicts
(prepare)    (CodeQL/Semgrep/     (rule,     (guided questions,     (TP/FP/NMD
              OpenGrep)            file,      multi-turn context)    + score)
                                   line)
```

The non-obvious part of the architecture: the CSV context store produced by `prepare` does not serve the `analyze` stage — it serves `verify`. Each time the model requests more context is one read of this store, so the cost of context expansion is a file read, not a re-run of static analysis.

| Stage | Command | Output |
|---|---|---|
| 1 | `prepare` | Source + CodeQL database + context CSV files |
| 2 | `analyze` | SARIF findings |
| 3 | `verify` | Verdict JSON with full reasoning |
| 4 | `report` | Markdown report (EN/VI) |

**3.1. Guided questions, per bug class**

This is the core component. Rather than one generic prompt, each `ruleId` in the SARIF is routed to its own question bank. VulnHunterX currently has **397 question templates** across 7 per-language banks (C/C++ 62, Python 67, Java 59, JavaScript 57, Go 54, PHP 52, C# 45) plus a fallback bank.

**Step 1 — pick the right question bank for the alert.** Each SAST engine names its rules differently, so the system tries two groups — match by **rule name** first (four variants), then match by **CWE** — stopping at the first that succeeds:

| Order | Match method | Example |
|---|---|---|
| 1 | Rule name matches a bank name exactly | CodeQL `cpp/use-after-free` → `cpp/use-after-free` bank |
| 2 | Normalize `-` to `/`, then match again | for engines that name with hyphens |
| 3 | Prefix match | `cpp/sql-injection` matches the `cpp/sql` bank |
| 4 | Same-language match | same `php/` prefix, rule name is a substring of the bank name |
| 5 | Match by CWE | Semgrep `vulnhunterx.php.file-inclusion` — no name match, but the rule declares `metadata.cwe: CWE-98`; the map sends `CWE-98 → file-inclusion` → `php/file-inclusion` bank |

The fifth tier matters most operationally: it lets **any custom rule reuse an existing bank without touching code**. A custom CodeQL query only needs to declare `@id cpp/my-rule`; a custom Semgrep rule only needs `metadata.cwe`. The map currently holds **124 CWE entries**. Only when all five miss does the system fall back to the generic bank.

**Step 2 — how the question bank is designed.** The crucial point is that these questions **do not ask "is this a bug"**. They are ordered in a fixed sequence: anchor the model to the exact line, force it to gather facts with checkable coordinates, and only then hand it the decision rule. The `cpp/use-after-free` bank has 10 questions in four groups:

| Question group | Its job | The typical mistake it blocks |
|---|---|---|
| **Q1** — anchor | Quote the exact statement at the flagged line, name the enclosing function, classify the line as a pointer use, a free call, or merely a declaration | The model commenting generically on the whole snippet instead of the exact line SAST flagged |
| **Q2** — scope | When the snippet contains several functions, identify which one the flagged line belongs to and reason only about it | Convicting merely because a sibling function looks like a UAF pattern or has a suggestive name |
| **Q3–4** — gather facts | Trace where the pointer is allocated; enumerate **every** free/delete call with function, file, and line; mark which frees are conditional | Concluding from a feeling, with no coordinate a reviewer can re-check |
| **Q5–9** — check defenses | Is the pointer set to NULL after free; the shortest control-flow path from free to use; does the pointer escape the function; are there aliases to the same memory; is it reassigned in between | Missing precisely the reasons a suspicious-looking UAF pattern is actually harmless |
| **Q10** — decision rule | The minimum needed to rule TP (a triple: free site, use site, and the control-flow path linking them) and the evidence required to rule FP (NULL-after-free, reallocation, an unreachable branch, or a flagged line that is only a declaration) | The model guessing when facts are missing, instead of returning `NEEDS_MORE_DATA` |

This structure is exactly why a small model still works: it does not have to invent what to check, nor set its own threshold for concluding — both are already in the prompt. The model's remaining job is to read the code and answer.

Below are the first four of ten, verbatim as loaded into the prompt from `config/prompts/cpp_questions.yaml`:

> - *"ANCHOR FIRST: quote the EXACT statement at the flagged line. Name the function it lives in. Classify the flagged line as one of: (a) a pointer USE (deref / read / write / pass-to-function), (b) a free/delete/destructor call, (c) a function signature or declaration, (d) something else. If (c) or (d), the SAST flag is suspect — record this and weight your verdict accordingly."*
> - *"If the snippet contains MULTIPLE functions (e.g. a vulnerable variant alongside a patched or test variant, or a helper alongside its caller), identify which function the flagged line belongs to. Reason ONLY about that function's behavior. Do NOT convict based on UAF patterns visible in sibling functions, regardless of how those functions are named."*
> - *"Where is the pointer at the flagged line ALLOCATED (malloc, calloc, new, strdup, custom allocator)? If allocation is in a DIFFERENT function, name that function — request 'caller:<func>' or 'all_callers:<func>' context if you cannot see it."*
> - *"List ALL free()/delete calls reachable from the flagged use — include the function name, file, and line number for EACH. If you cannot enumerate them from the snippet, request 'free_sites:<pointer_name>' context. Mark which frees are conditional (inside if/switch/error paths)."*

Beyond the question list, each bank declares three fields that control the engine's behavior. For `cpp/use-after-free`:

- `additional_context: [free_sites, caller, all_callers, struct, callees, destructor, field_writes]` — the context types the model is allowed to request for this bug class.
- `context_hint` — a suggested order: fetch the pointer's `free_sites` first, then where it is allocated, its type definition, and the destructor of its owning class.
- `min_iterations: 3` — the minimum number of conversation rounds, i.e. the model **is not allowed** to conclude on its very first answer.

**3.2. Answer first, conclude second**

The question bank only works if the model is *forced* to answer all of it before it may conclude. That constraint lives in the system prompt as a mandatory six-step procedure, in strict order:

| Step | Requirement | Why it is needed |
|---|---|---|
| 0 | **Locate the flagged line**: find it by line number in the numbered code block, quote its exact text, confirm the construct the rule describes is actually there | Blocks reasoning about a different snippet than the one SAST flagged |
| 1 | **Identify the vulnerability class** from the rule id and description | Selects the right reasoning frame |
| 2 | **Answer every guided question**, based only on the provided code, citing line numbers; if something is not visible, say *"Not visible in provided context"* | Forces every claim to carry a checkable coordinate, and forces the model to admit missing facts |
| 3 | **Trace the dataflow**: source → transform/sanitizer → sink, listing each step with line numbers | Separates "a path exists" from "it looks dangerous" |
| 4 | **Evaluate reachability and exploitability** of that path | A dangerous sink on an unreachable branch is not a bug |
| 5 | **Only now** may the verdict be given | — |

Three principles that accompany the procedure matter as much as the questions themselves:

- **Asymmetric evidence bar.** To rule *False Positive*, the model must point to a **specific, visible** defense in the code — a bounds check, a sanitizer call, a type guarantee, or a framework mechanism. The exact constraint in the prompt: *"Absence of evidence of a vulnerability is NOT evidence of safety."* The model is also forbidden from inferring safety from a function's name or from attributes such as `static` or `__init`.
- **If it cannot see it, it cannot conclude.** If the flagged line is not present in the provided code, the model **may not** answer *False Positive* — it must return *Needs More Data* and request the missing code. This directly blocks the worst failure mode of LLM triage: fabricating a safe verdict for a line it never read.
- **The rule locates a sink; it does not fix the bug class.** If the flagged sink is genuinely exploitable, the model must rule *True Positive* even when the real class differs from the rule's CWE — naming the real class in its reasoning. Conversely, it is forbidden from "borrowing" a different bug at a different line to justify the alert under review.

The prompt also teaches the model to read rule metadata correctly: `precision: high` describes the reliability of the **pattern** across a corpus, and says nothing about whether **this instance** is exploitable; `security-severity` is the rule's worst-case rating, useful only to prioritize reviewer attention, never a reason to lean toward True Positive.

The result of all these constraints is a change in the nature of the output: **a verdict without an answer sheet is unfalsifiable; a verdict with one, where every claim points to a specific line number, is reviewable in thirty seconds** — you just open the three cited line numbers and check.

**3.3. Multi-turn context expansion**

When the model finds it lacks a fact, it can request more context from a fixed vocabulary, and the engine serves the request from the CSV store:

| Request | What it returns |
|---|---|
| `caller:` / `all_callers:` | The calling function's code / all callers (up to 10) |
| `function:` / `callees:` / `callee_bodies:` | The sink function's body, the list of functions it calls, and their bodies |
| `struct:` / `typedef:` / `enum:` | Type definition, type alias, enum with its values |
| `global:` / `macro:` | Global variable declaration, macro definition |
| `free_sites:` | Every free()/delete/destructor site for a pointer across the whole repo (C/C++) |
| `destructor:` / `field_writes:` | Destructor body, every write site of a field (C/C++, for RAII and TOCTOU) |
| `framework_sanitizers:` / `framework_guards:` | The validation boundary and auth guards at the framework layer (e.g. NestJS `ValidationPipe`, `APP_GUARD`) |

Two conditions must both hold for the loop to stop: the model requests no more context *and* it has run the minimum rounds for that bug class. For use-after-free, `min_iterations: 3` means a first-round conclusion is blocked even when the model is confident. On the in-house suite, the mean is **2.49 rounds per finding**.

The prompt always includes the **dataflow path extracted by the SAST engine itself**, annotated `[SOURCE]` / `[TRANSFORM]` / `[SINK]` per step. VulnHunterX does not rebuild the DFG — it reuses the dataflow analysis that is CodeQL's strength, then adds what SAST does not provide: the call graph, type definitions, and object lifetimes.

**3.4. The output**

The model may not answer freely. It must return a strictly-structured JSON envelope, and the engine saves each finding as a file under `output/<lang>/<repo>/verification_results/`. The envelope has seven fields:

| Field | Contents |
|---|---|
| `answers[]` | The answer sheet — one element per guided question, with line citations |
| `data_flow` | The traced flow, as `source (line N) → transform (line M) → sink (line K)` |
| `verdict` | `True Positive` / `False Positive` / `Needs More Data` |
| `confidence` | `High` / `Medium` / `Low` — exactly one of the three |
| `confidence_score` | A 0.0–1.0 score; if the model gives none, the engine maps it from the categorical level (High = 0.85, Medium = 0.6, Low = 0.3) |
| `reasoning` | A sentence or two, required to reference the answer sheet and the dataflow |
| `context_needed[]` | The missing context, used to trigger the next conversation round |

Alongside the model-generated part, the engine records the measurements of the run itself: `iterations`, `model`, `timestamp`, `elapsed_seconds`, `input_tokens` / `output_tokens` / `cached_input_tokens`, and `cost_usd`. Because of this, every cost figure in Section 4 is traceable back to an individual finding, rather than being an estimate.

Below is a real verdict, metadata trimmed, for a `double-free` alert reported by Semgrep at `dvcp.c:62`:

```json
{
  "finding": {
    "rule_id": "c.lang.security.double-free.double-free",
    "message": "Variable 'buff1' was freed twice...",
    "file": "repos/c/dvcp/dvcp.c",
    "start_line": 62,
    "precision": "very-high",
    "cwe_ids": ["CWE-415"],
    "tool": "Semgrep"
  },
  "verdict": "False Positive",
  "confidence": "Low",
  "confidence_score": 0.55,
  "reasoning": "The flagged free is in a different file/function than the
     only other known free sites, and no control-flow path linking them is
     provided. Without evidence of a prior free of the same memory in the
     same execution context, the double-free claim is unsupported.",
  "answers": [
    "Flagged line: dvcp.c:62 `free(buff1);` — a free call.",
    "Only the `if` block is shown; the containing function is unknown.",
    "Only two free sites for buff1 listed: imgRead.c:59 and imgRead.c:62
       (both in ProcessImage). The flagged free at dvcp.c:62 is not
       accounted for in that list.",
    "No code path shown that connects the flagged free to any other free.",
    "No NULL assignment visible."
  ],
  "iterations": 3,
  "model": "deepseek-v4-flash",
  "input_tokens": 10324,
  "output_tokens": 3654,
  "cached_input_tokens": 6016
}
```

This record illustrates exactly what Section 3.2 describes. The rule declares `precision: very-high`, but the model does not take that as evidence. It enumerates **exactly** the two known free sites with file and line, shows that the flagged line is not among them, and lowers confidence to `Low` rather than asserting certainty.

The three verdict values are used as follows in practice:

- **True Positive** — queued for handling, ordered by `confidence_score` and severity.
- **False Positive** — closed, but the answer sheet is retained so the decision can be audited later. This is the difference from filtering by regex or an exclude-list: every dismissal comes with a reason that has coordinates.
- **Needs More Data** — a state that is retained **deliberately**. A triage system that can say "I don't have enough facts" is far more useful than one that always answers, because it turns the hard cases into a short list for a human rather than mixing lucky guesses into the same pile as grounded conclusions. Across the 125-finding regression suite, only **one** case landed here.

---

**4. Experimental results**

**4.1. The in-house regression suite**

This suite has 125 findings from four deliberately-vulnerable targets — **dvcp** (C), **dvwa** (PHP), **insecure-coding-examples** (C/C++), **nodegoat** (JavaScript) — with hand-built ground truth: 88 real bugs, 37 false alarms.

| | Precision | Recall |
|---|---|---|
| Raw SAST (every alert taken as real) | 70% | 100% |
| **VulnHunterX** | **92%** | **95%** |

Cost for the full 125 findings: **$14.58**, about **$0.12 per finding**, at a 69% prompt-cache hit rate.

**4.2. How much the guided questions contribute**

On OWASP BenchmarkPython (300 cases), the benchmark framework compares four approaches: `raw-sast` (no LLM), `ablation-zero` (LLM, no questions), `ablation-generic` (generic questions), and `vulnhunterx` (rule-specific guided questions).

| Approach | Model | Precision | Recall | FP-reduction |
|---|---|---|---|---|
| raw-sast | — | 37.7% | 100% | 0% |
| ablation-zero (no questions) | DeepSeek | 77.3% | 96.5% | 82.9% |
| ablation-generic (generic questions) | DeepSeek | 81.1% | 94.7% | 86.6% |
| **vulnhunterx (guided questions)** | **DeepSeek** | **87.3%** | **98.2%** | **91.4%** |

This is the cleanest result in the whole set: the full pipeline beats both ablations on **precision and recall**, for every model tested. Across all four datasets, with the strongest model tested, the system cuts false positives by **78.6%–91.4%** while retaining **87.5%–98.2%** of the real bugs.

**4.3. You do not need a strong LLM**

This is the most operationally valuable result, because it determines running cost. Same OWASP BenchmarkPython, same pipeline, only the model changes.

| Model | Precision | Recall | FP-reduction | Cost |
|---|---|---|---|---|
| raw-sast (no LLM) | 37.7% | 100% | 0% | — |
| qwen3-coder (ollama, local) | 65.3% | 99.1% | 68.5% | **$0** |
| gpt-4.1-mini | 82.7% | 97.4% | 87.7% | $1.10 |
| DeepSeek | 87.3% | 98.2% | 91.4% | $0.40 |

A mini model takes precision from 37.7% to 82.7% — a **87.7%** cut in wasted triage — only 4.6 points behind the strongest. A model running entirely locally, at zero API cost, still cuts more than two-thirds of the false alarms while keeping 99.1% of the real bugs.

More telling than the absolute number is how much the scaffolding contributes to the weak model itself. For gpt-4.1-mini on the same dataset: no guided questions → 64.0% precision; generic questions → 59.1%; rule-specific guided questions → **82.7%**. The right question bank gives the small model **over 18 points of precision** — more than the gap between it and the large model.

The SecLLMHolmes results make this even clearer once you put it in dollars:

| Model | Precision | Recall | Cost, full set |
|---|---|---|---|
| gpt-5 | 78.4% | 85.9% | $16.75 |
| DeepSeek | 82.1% | 87.5% | n/a (*) |
| gpt-4.1-mini | 74.7% | 89.9% | $0.73 |
| qwen3-coder (local) | 70.5% | 87.8% | **$0** |

(*) LiteLLM has no price for DeepSeek, so the harness records $0; the real cost is one to two orders of magnitude below gpt-5.

The local model is only **7.9 precision points** behind `gpt-5`, while `gpt-5` costs $16.75 for the same workload — and `gpt-5` is not even the best model in the table. For a security team that cannot send source code off-premises, this is the difference between "usable" and "not usable".

**4.4. Where that conclusion ends**

The small model's advantage is uneven across bug classes. On Juliet C/C++ — which tests memory-safety reasoning — gpt-4.1-mini cuts only **23.9%** of false positives, while DeepSeek reaches **82.2%** on the same dataset and pipeline. Two local-model runs on OWASP BenchmarkJava abstained on essentially every finding — recorded as "100% FP-reduction" but really a failure wearing a success metric's clothes, and those rows are kept in the published comparison tables.

The honest conclusion: **for common web bug classes (injection, path traversal, XSS, deserialization), a small or local model plus good scaffolding is production-usable; for memory-lifetime reasoning in C/C++, scaffolding does not substitute for model capability.**

Guided questions are also not always beneficial. On Juliet, `ablation-generic` (88.1%/98.9%) *beat* the full pipeline (83.8%/93.8%) with DeepSeek. Our read: Juliet's synthetic `bad()`/`good()` function pairs are self-contained by construction, so rule-specific questions only lengthen the prompt without adding signal, and sometimes talk the model into over-thinking a two-line case. Guided questions earn their keep on real code, where source and sink are separated by several call layers.

---

**5. Multi-language support: both compiled and interpreted**

VulnHunterX supports **8 languages**, covering both families:

| Family | Language | Context source for verification |
|---|---|---|
| Compiled | C, C++ | CodeQL DB — 14 extraction queries: functions, callers, structs, globals, macros, enums, typedefs, free_sites, destructors, field_writes… |
| Compiled | Java | CodeQL DB — functions, callers, classes |
| Compiled | Go, C# | CodeQL DB — functions, callers, classes |
| Interpreted | Python | CodeQL DB — functions, callers, classes |
| Interpreted | JavaScript | CodeQL DB — functions, callers, classes |
| Interpreted | PHP | tree-sitter (when no CodeQL database can be built) |

The technically interesting part is the **fallback mechanism**: when no CodeQL database can be built — because the language is unsupported, the build fails, or the repo lacks a toolchain — the system extracts context with tree-sitter, which only needs to parse syntax, not compile. The context is lower-quality, since there is no precise interprocedural call graph, but the verification pipeline still runs instead of halting. This is why PHP — the language DVWA belongs to, and the one accounting for 72 of the 125 findings in the in-house suite — still reaches 89% precision / 100% recall.

On the SAST side, the system runs with three engines (CodeQL, Semgrep, OpenGrep) and five rule profiles from `standard` to `full`, where `full` layers 64 custom CodeQL queries and 103 custom Semgrep rules on top of the built-in suites. On the LLM side, any provider LiteLLM speaks is usable: OpenAI, Anthropic, Gemini, DeepSeek, and Ollama (local or cloud).

```bash
vuln-hunter-x scan --url https://github.com/org/app.git --lang python --profile full --limit 10
```

---

**6. What this tool cannot do**

- **Absence-of-control bugs are out of reach.** Missing authorization, disabled CSRF middleware, no rate limiting — SAST does not reliably flag these, so there is nothing for the verifier to verify. Reports carry an explicit coverage-limitation caveat for exactly this reason.
- **Quality is bounded by the input SAST.** The verifier can only remove false alarms; it cannot create an alert the upstream engine missed. The system's recall is capped by the SAST's recall.
- **On synthetic fixtures, guided questions can backfire** — as shown in Section 4.4.

---

**7. Conclusion**

The real-world SAST problem is not detection, it is triage. And triage is not a problem that needs a smarter model — it is a problem that needs **the right context, delivered at the right moment, to a model that is forced to answer exactly the questions its bug class demands**.

Once you separate those two things, the result is precision rising from 37.7% to 82.7% *with a mini model*, and to 65.3% with a model running entirely on local hardware at zero API cost. Most of the value lives in the 397 guided-question templates and the multi-turn context-request loop, not in model size.

VulnHunterX is open source under the MIT license:

```bash
git clone https://github.com/vinsoc-cyber/VulnHunterX.git && cd VulnHunterX
uv venv --python python3.12 .venv && source .venv/bin/activate
uv pip install -e ".[dev]"
cp env.example .env        # add your provider key
vuln-hunter-x check-env    # verify the toolchain
vuln-hunter-x interactive  # guided wizard, no flags to remember
```

**VinSOC Research Team.**

---

***References***

*[1] CyberArk Labs — Vulnhalla: Picking the True Vulnerabilities from the CodeQL Haystack — CyberArk Threat Research Blog (https://www.cyberark.com/resources/threat-research-blog/vulnhalla-picking-the-true-vulnerabilities-from-the-codeql-haystack)*

*[2] VulnHunterX — source code and documentation — GitHub Repository (https://github.com/vinsoc-cyber/VulnHunterX)*

*[3] OWASP Benchmark Project — ground-truth datasets for Java and Python (https://owasp.org/www-project-benchmark/)*

*[4] NIST SARD — Juliet Test Suite for C/C++ v1.3.1 (https://samate.nist.gov/SARD/test-suites)*

*[5] SecLLMHolmes — a benchmark for LLM vulnerability-reasoning ability (https://github.com/ai4cloudops/SecLLMHolmes)*

*[6] GitHub — CodeQL CLI Documentation (https://codeql.github.com/docs/codeql-cli/)*

*[7] BerriAI — LiteLLM: a unified interface to 100+ LLM providers (https://github.com/BerriAI/litellm)*

---

*Benchmark figures: the version-A/B regression suite run on 2026-07-12 on `gpt-5.5` at temperature 0; the public-dataset matrices run from 2026-05-31 to 2026-06-05. All result files are committed under `benchmark/result/` and `benchmarks/results/`.*
