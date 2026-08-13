# cpp/static-buffer-overflow @ practice/if_constexpr.cpp:15

**Verdict:** TP · **Confidence:** Low (0.45) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The `memcpy` call copies `first_len` bytes (INT_MAX) into a 256‑byte buffer, which would overflow if the code is compiled. The `if constexpr` guard relies on a constant‑expression that involves signed overflow, making its outcome undefined; thus the guard does not reliably eliminate the unsafe `memcpy`. Consequently an exploitable overflow exists. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. a) The only defense visible is the `if constexpr` statement on line 14: `if constexpr ((first_len + second_len) <= buf_len) { … }`. This is a compile‑time conditional that, if evaluated to false, discards the block containing the `memcpy` calls.
2. b) The defense would cover all reachable paths only if the condition on line 14 is guaranteed to evaluate to false at compile time, because `if constexpr` removes the guarded statements from the generated program when the condition is false. In that case the `memcpy` calls on lines 15‑16 would never be compiled or executed, eliminating any path to the sink.
3. c) The static‑buffer‑overflow rule looks for a call to `memcpy` (or similar memory‑copy functions) where the size argument can be larger than the destination buffer size. It flags the call on line 15 (`memcpy(buf, first, first_len)`) because `first_len` is a compile‑time constant equal to `std::numeric_limits<int>::max()`, which is far larger than the destination buffer `buf` of size 256 (declared on line 11). The rule does not analyse the surrounding `if constexpr` guard, so it reports a potential overflow.
4. Additional context: The expression `(first_len + second_len)` on line 14 overflows a signed `int` (INT_MAX + 256), which is undefined behaviour in a constant expression. Compilers may reject the program, or, with non‑strict‑overflow settings, may wrap the value and make the condition true, causing the guarded block to be compiled. Because the behaviour of the guard is not guaranteed, the defense cannot be proven to cover all reachable paths from the code shown.
