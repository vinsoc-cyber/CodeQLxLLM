# cpp/overflow-buffer @ practice/if_constexpr.cpp:15

**Verdict:** TP · **Confidence:** High (0.92) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code copies 2 GB of data (line 15) into a 256‑byte buffer (line 10) with no effective bounds check; the compile‑time condition overflows, making the unsafe memcpy reachable, which constitutes a clear buffer‑overflow vulnerability.

## Data flow

source (first_len defined line 8) → condition (line 14) → memcpy (sink line 15)

## Answers

1. 1. The data originates from the local stack array `first` defined at line 11. Its size is determined by the constant `first_len` (line 8), which is set to `std::numeric_limits<int>::max()` – not from any external user input.
2. 2. Flow: `first_len` is defined at line 8, `second_len` at line 9, `buf_len` at line 10. Arrays `first`, `second`, and `buf` are allocated at line 11 using those lengths. The `if constexpr` condition at line 14 uses `first_len`, `second_len`, and `buf_len`. Inside the true branch, `memcpy(buf, first, first_len)` at line 15 copies `first_len` bytes from `first` to `buf`. Then `memcpy(buf + first_len, second, second_len)` at line 16 copies `second_len` bytes.
3. 3. No validation or sanitisation is performed on the length values. The only guard is the `if constexpr` condition at line 14, which is intended to ensure the total copy size fits, but due to signed‑int overflow it can evaluate incorrectly, providing no effective protection.
4. 4. The sink is the `memcpy` call at line 15 (and line 16). `memcpy` copies a number of bytes (`first_len` = 2,147,483,647) into `buf`, which is only 256 bytes long (line 10), causing a buffer overflow.
5. 5. The standard library `memcpy` does not perform any automatic bounds checking, and no framework or library wrapper is used here.
6. 6. The code resides in `main()` and runs with the privileges of the process that executes the program. No authentication or privilege checks are performed; any attacker who can cause the program to run can trigger the overflow.
7. 7. An overflow of a stack buffer can corrupt the stack, potentially leading to a crash (Denial‑of‑Service) or, if an attacker can influence the contents of `first`, arbitrary code execution (RCE).
8. 8. The weakest link is the missing and incorrect bounds check: the `if constexpr` condition at line 14 relies on arithmetic that overflows, so it does not reliably prevent the unsafe `memcpy` at line 15.
