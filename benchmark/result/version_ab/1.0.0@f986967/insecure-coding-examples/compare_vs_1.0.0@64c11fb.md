# Compare — 1.0.0@64c11fb → 1.0.0@f986967

Δprecision **+3%** · Δrecall **-8%** · 2026-08-13T17:13:44

## Flips: 5 (improve 1 · regress 3 · neutral 1)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| cpp/overflow-buffer@practice/if_constexpr.cpp:15 | real | TP → FP | REGRESS | High→High |
| cpp/static-buffer-overflow@practice/if_constexpr.cpp:15 | real | TP → FP | REGRESS | Low→High |
| cpp/suspicious-sizeof@practice/decay.cpp:5 | not-real | NMD → FP | IMPROVE | Medium→High |
| cpp/suspicious-sizeof@practice/guidelines/expressions_and_statements/cautious_pointer_use_decay.cpp:10 | not-real | FP → NMD | REGRESS | High→Low |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:13 | not-real | TP → NMD | neutral | Low→Low |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | +$0.00         |
| input tokens      | +15k           |
| output tokens     | +2k            |
| cache hit ratio   | +0.0pp         |
| model time        | -36.9s         |
| iterations (mean) | +0.03          |
| errors            | +0             |
| abstentions       | +1             |
