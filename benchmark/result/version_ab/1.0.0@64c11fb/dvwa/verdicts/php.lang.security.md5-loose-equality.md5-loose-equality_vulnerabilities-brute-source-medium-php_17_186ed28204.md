# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/medium.php:17

**Verdict:** FP · **Confidence:** High (0.94) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged `==` compares two integers, not an MD5 string, so the type‑juggling issue the rule guards against cannot occur. The rule mis‑matched the MD5 computation with an unrelated equality check. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) The only “defense” present is that the comparison on line 17 `mysqli_num_rows( $result ) == 1` is between two integers – the return value of `mysqli_num_rows()` (always an int) and the literal `1` (int). No string or MD5 value participates in this comparison.
2. (b) Because `mysqli_num_rows()` cannot return a non‑integer, every reachable execution of the `if` statement evaluates an integer against an integer. Therefore there is no type‑juggling path that could turn the loose `==` into a security issue; the comparison is safe on all paths that reach line 17.
3. (c) The Semgrep rule `php.lang.security.md5-loose-equality.md5-loose-equality` simply looks for a loose equality operator (`==`) in code that also contains an `md5()` call somewhere in the same function. It does not verify that the operands of `==` are the MD5 values. In this snippet the MD5 hash is computed on line 11 (`$pass = md5( $pass );`) but never compared with `==`. The rule therefore incorrectly associates the `==` on line 17 with the earlier MD5 computation, resulting in a false positive.
