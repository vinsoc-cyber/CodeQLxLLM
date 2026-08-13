# Score — 1.0.0@f986967

Model `ollama/gpt-oss:120b` · temp `0` · panel `sha256:9cdeda155…` · 2026-08-13T16:50:02

precision **92%** · recall **92%** · TP 26 (real 24, false-alarm 2) · real 26 · not-real 6 · NMD 3 · err 0 · $0.0
_resources:_ 168k in / 46k out · cache 0% · 702.1s model-time · iters μ1.34

| finding | truth | verdict | grade | conf |
|---|---|---|---|---|
| cpp/dangerous-cin@exploit/wargames/launch_bigger.cpp:19 | real | TP | CORRECT | High |
| cpp/dangerous-cin@exploit/wargames/launch.cpp:19 | real | TP | CORRECT | High |
| cpp/dangerous-function-overflow@exploit/wargames/launch.c:19 | real | TP | CORRECT | High |
| cpp/dangerous-function-overflow@exploitable/stack_buffer_overflow.c:13 | real | TP | CORRECT | High |
| cpp/double-free@exploitable/double_free.c:15 | real | TP | CORRECT | High |
| cpp/non-constant-format@exploit/format/direct_access.c:7 | real | TP | CORRECT | High |
| cpp/non-constant-format@exploit/format/exploitable.c:66 | real | TP | CORRECT | High |
| cpp/non-constant-format@exploit/format/exploitable_simple.c:12 | real | TP | CORRECT | High |
| cpp/non-constant-format@exploitable/uncontrolled_format_string.c:14 | real | TP | CORRECT | High |
| cpp/overflow-buffer@exploitable/global_buffer_overflow.c:9 | real | TP | CORRECT | High |
| cpp/overflow-buffer@practice/if_constexpr.cpp:15 | real | FP | MISS | High |
| cpp/signed-overflow-check@exploitable/signed_integer_overflow.c:16 | real | TP | CORRECT | Low |
| cpp/signed-overflow-check@exploitable/undefined_behavior.cpp:11 | not-real | TP | FALSE-ALARM | Low |
| cpp/signed-overflow-check@exploitable/undefined_behavior.cpp:15 | not-real | TP | FALSE-ALARM | Low |
| cpp/signed-overflow-check@practice/if_constexpr.cpp:14 | real | TP | CORRECT | Low |
| cpp/static-buffer-overflow@practice/if_constexpr.cpp:15 | real | FP | MISS | High |
| cpp/suspicious-sizeof@practice/decay.cpp:5 | not-real | FP | CORRECT | High |
| cpp/suspicious-sizeof@practice/guidelines/expressions_and_statements/cautious_pointer_use_decay.cpp:10 | not-real | NMD | abstain | Low |
| cpp/tainted-format-string@exploit/format/direct_access.c:7 | real | TP | CORRECT | High |
| cpp/tainted-format-string@exploit/format/exploitable.c:66 | real | TP | CORRECT | High |
| cpp/tainted-format-string@exploit/format/exploitable_simple.c:12 | real | TP | CORRECT | High |
| cpp/tainted-format-string@exploitable/uncontrolled_format_string.c:14 | real | TP | CORRECT | High |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:13 | not-real | NMD | abstain | Low |
| cpp/type-confusion@practice/guidelines/expressions_and_statements/use_named_cast.cpp:16 | not-real | NMD | abstain | Medium |
| cpp/unbounded-write@exploit/format/exploitable.c:64 | real | TP | CORRECT | High |
| cpp/unbounded-write@exploit/format/exploitable_simple.c:11 | real | TP | CORRECT | High |
| cpp/unbounded-write@exploit/wargames/launch.c:19 | real | TP | CORRECT | High |
| cpp/unbounded-write@exploitable/heap_buffer_overflow.c:14 | real | TP | CORRECT | High |
| cpp/unbounded-write@exploitable/heap_buffer_overflow_cwe.c:14 | real | TP | CORRECT | High |
| cpp/unbounded-write@exploitable/stack_buffer_overflow.c:13 | real | TP | CORRECT | High |
| cpp/unbounded-write@exploitable/stack_buffer_overflow_cwe.c:13 | real | TP | CORRECT | High |
| cpp/use-after-free@exploitable/use_after_free.c:19 | real | TP | CORRECT | High |
