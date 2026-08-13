# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:13

**Verdict:** NMD · **Confidence:** Low (0.0) · **Truth:** not-real · **Grade:** abstain · **Iterations:** 2

## Reasoning

{
  "answers": [
    "(a) No specific defense is observed in the provided snippet. There is no check, validation, or safe cast before the conversion on line 13.",
    "(b) Because no defense is present, we cannot demonstrate that all reachable paths to the sink are protected. The snippet shows only the unsafe C‑style cast without any guard.",
    "(c) The `cpp/type-confusion` rule looks for a cast that converts a pointer of one class type to an unrelated class type without using a safe cast (e.g [second-opinion pass after 1-iter high-conf FP]
