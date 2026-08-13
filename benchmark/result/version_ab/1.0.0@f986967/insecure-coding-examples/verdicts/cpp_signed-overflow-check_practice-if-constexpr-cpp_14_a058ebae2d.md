# cpp/signed-overflow-check @ practice/if_constexpr.cpp:14

**Verdict:** TP · **Confidence:** Low (0.45) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The SAST rule flags any signed addition that can overflow, regardless of whether the operands are attacker‑controlled. The code adds `INT_MAX` and `256` on line 14, which overflows a signed `int` and yields undefined behaviour—meeting the rule's pattern. No defense (e.g., bounds check) is present in the snippet, so the finding is a genuine overflow bug. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. 1. The data originates from compile‑time constant literals: `first_len` is set to `std::numeric_limits<int>::max()` on line 8, `second_len` and `buf_len` are set to the literal `256` on lines 9‑10. No external source (user, file, network) is involved.
2. 2. Data flow: line 8 defines `first_len`; line 9 defines `second_len`; line 10 defines `buf_len`; line 14 evaluates the expression `(first_len + second_len) <= buf_len`, performing the addition `first_len + second_len` which can overflow.
3. 3. No validation, sanitization, or encoding is performed on these constants. The only operation is the unchecked signed addition on line 14.
4. 4. The sink is the evaluation of the constant‑expression in the `if constexpr` condition on line 14. Computing `first_len + second_len` may overflow, leading to undefined behaviour.
5. 5. The C++ language and standard library do **not** provide automatic protection against signed integer overflow in constant‑expression evaluation. `if constexpr` merely requires the condition to be a valid constant expression; it does not guard against overflow.
6. 6. Because the inputs are compile‑time constants, no attacker can influence this path. No privilege or authentication context is relevant.
7. 7. The impact is limited to a correctness issue: the program may fail to compile or exhibit undefined behaviour at runtime. It does not enable RCE, data theft, privilege escalation, or DoS.
8. 8. The weakest link is the lack of any overflow check before the addition on line 14. However, since the operands are not attacker‑controlled, the weakness does not translate into a security vulnerability.
