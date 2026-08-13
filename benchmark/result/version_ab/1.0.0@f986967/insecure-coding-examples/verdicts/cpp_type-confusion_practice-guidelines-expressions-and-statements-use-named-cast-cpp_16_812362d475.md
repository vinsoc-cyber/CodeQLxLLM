# cpp/type-confusion @ practice/guidelines/expressions_and_statements/use_named_cast.cpp:16

**Verdict:** NMD · **Confidence:** Medium (0.65) · **Truth:** not-real · **Grade:** abstain · **Iterations:** 2

## Reasoning

The snippet shows an unsafe cast but no downstream use of the resulting pointer; without seeing whether `tony3` is later dereferenced, we cannot decide if the type‑confusion leads to an exploitable issue. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. a) No specific defense is present in the provided snippet. The only operations are a `new` allocation (line 12) and an unsafe `reinterpret_cast` (line 16). There is no bounds check, type check, or validation.
2. b) Because no defense exists, we cannot demonstrate that it covers all reachable paths to the sink. The cast on line 16 is performed unconditionally on the pointer returned by `new` at line 12.
3. c) The `cpp/type-confusion` rule flags any use of C‑style casts, `reinterpret_cast`, or similar constructions that convert a pointer/reference from one unrelated class type to another. It does not require the source to be attacker‑controlled; it simply warns that the conversion is invalid and may lead to undefined behaviour if the resulting pointer is dereferenced. The rule therefore flags line 16 because `reinterpret_cast<Ironman *>(peter)` converts a `Spiderman*` to an unrelated type without any run‑time check.

## Context needed

- function:main
