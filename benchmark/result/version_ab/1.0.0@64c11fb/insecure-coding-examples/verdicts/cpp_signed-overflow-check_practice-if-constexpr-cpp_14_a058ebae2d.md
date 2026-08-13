# cpp/signed-overflow-check @ practice/if_constexpr.cpp:14

**Verdict:** TP · **Confidence:** Low (0.45) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The code performs a signed‑integer addition that can overflow (line 14) and uses the result to decide whether to execute `memcpy`. The overflow makes the condition undefined, so the intended safety check is unreliable. No defensive check is present, matching the rule's pattern. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) No specific defense is present in the shown code. There is no bound check, no use of safe arithmetic, and no library call that prevents overflow. The only conditional is the `if constexpr` on line 14, which itself performs the addition that can overflow.
2. (b) Because there is no defense, there is no mechanism that covers any reachable path to the sink. The `memcpy` calls on lines 15‑16 will be compiled only if the constexpr condition evaluates to true, but the evaluation itself invokes undefined signed‑integer overflow, so the intended safety check is ineffective.
3. (c) The `cpp/signed-overflow-check` rule flags any expression that tests a condition involving a signed integer operation that may overflow (e.g., `a + b` where `a` or `b` can be near `INT_MAX`). Here the rule matches the addition `first_len + second_len` on line 14. The rule does not require a surrounding guard; it simply warns that the test may itself be undefined.
