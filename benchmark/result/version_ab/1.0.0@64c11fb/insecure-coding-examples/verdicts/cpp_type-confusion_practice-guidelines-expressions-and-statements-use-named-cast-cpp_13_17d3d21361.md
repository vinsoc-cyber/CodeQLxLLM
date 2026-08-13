# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:13

**Verdict:** TP · **Confidence:** Low (0.45) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

The code performs an unchecked C‑style cast between unrelated class types with no validation, matching the type‑confusion pattern; no defense is visible, making the finding a genuine issue. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) No specific defense is present in the shown code. There is no runtime check, static_cast, or other guard on line 13; the statement is a plain C‑style cast: `Ironman * tony1 = (Ironman *)peter;`.
2. (b) Because no defense exists, there is nothing that covers reachable paths to the sink. The cast on line 13 is executed unconditionally and could be used later without any type verification.
3. (c) The `cpp/type-confusion` rule flags conversions between unrelated class pointer types performed via C‑style casts or `reinterpret_cast`. It matches the pattern of a cast from `Spiderman*` to `Ironman*` on line 13, which bypasses the C++ type system and can lead to undefined behaviour if the resulting pointer is dereferenced. The (non‑existent) code does not perform any check that would satisfy the rule’s expectation of a safe cast (e.g., `dynamic_cast` with a null‑check).
