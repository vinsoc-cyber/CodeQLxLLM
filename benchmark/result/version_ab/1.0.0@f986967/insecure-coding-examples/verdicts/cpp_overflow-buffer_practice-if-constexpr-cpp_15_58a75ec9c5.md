# cpp/overflow-buffer @ practice/if_constexpr.cpp:15

**Verdict:** FP · **Confidence:** High (0.92) · **Truth:** real · **Grade:** MISS · **Iterations:** 2

## Reasoning

The `if constexpr` guard on line 14 eliminates the memcpy block at compile time, so the dangerous copy can never be executed; the static analyzer missed this compile‑time guard. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) The only explicit defense is the `if constexpr` statement on line 14:
    `if constexpr ((first_len + second_len) <= buf_len) {` – this is evaluated at compile time.
    (b) Because the condition is a constant expression, the compiler will either:
        • evaluate it as **false** (the usual case when the addition does not overflow) and completely discard the block containing the `memcpy` calls, or
        • reject the program as ill‑formed if the addition overflows (signed‑int overflow is undefined behaviour and makes the expression non‑constant). In either situation, **no executable path can reach the `memcpy` on line 15**.
    Since the block is removed at compile time, there is no runtime path that reaches the sink.
    (c) The `cpp/overflow-buffer` rule flags any call to `memcpy` where the third argument (the byte count) can be larger than the size of the destination buffer. It does **not** analyse `if constexpr` guards or the fact that the program may be ill‑formed; it simply sees `memcpy(buf, first, first_len)` where `first_len` (2 147 483 647) exceeds `sizeof(buf)` (256) and raises a finding.
    The defense we identified (line 14) is therefore invisible to the rule, leading to the false positive.
