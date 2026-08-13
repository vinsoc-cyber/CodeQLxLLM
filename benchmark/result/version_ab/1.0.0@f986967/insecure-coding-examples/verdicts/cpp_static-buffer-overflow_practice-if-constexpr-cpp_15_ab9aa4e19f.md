# cpp/static-buffer-overflow @ practice/if_constexpr.cpp:15

**Verdict:** FP · **Confidence:** High (0.93) · **Truth:** real · **Grade:** MISS · **Iterations:** 2

## Reasoning

The `if constexpr` on line 14 guarantees the block containing the unsafe `memcpy` (line 15) is never compiled, eliminating the overflow risk despite the static analysis rule matching the pattern. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) Defense observed: the compile‑time guard `if constexpr ((first_len + second_len) <= buf_len) { … }` on line 14. Because the condition is a `constexpr` expression, the compiler either discards the whole block or rejects the program; in either case the `memcpy` calls on lines 15‑16 are never emitted as executable code.
2. (b) Coverage of all paths: `if constexpr` is evaluated at compile time, so when the condition is false (as it is here, since `first_len` is `INT_MAX` and the summed value cannot be ≤ `buf_len`), the statements inside the block, including the dangerous `memcpy` at line 15, are not part of the generated binary. Therefore there exists no runtime path that reaches the sink.
3. (c) Reason for the SAST flag: the rule `cpp/static-buffer-overflow` simply looks for a `memcpy` (or similar) where the length argument (`first_len` on line 15) can be larger than the destination buffer size (`buf_len` = 256). It does not evaluate `if constexpr` guards, so it incorrectly assumes the `memcpy` is reachable and flags a potential overflow.
