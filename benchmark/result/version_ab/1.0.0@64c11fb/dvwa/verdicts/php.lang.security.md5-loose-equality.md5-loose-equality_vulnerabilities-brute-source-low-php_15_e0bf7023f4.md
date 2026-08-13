# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/low.php:15

**Verdict:** FP · **Confidence:** High (0.94) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line does not perform a loose equality check on an MD5 value; therefore the rule’s condition is not met and the finding is a false positive. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) The only comparison on the flagged line is `mysqli_num_rows( $result ) == 1` (line 15). It compares an integer row count to the literal `1`; no MD5 value is involved, so there is no vulnerable loose‑equality of hashes.
2. (b) Because the comparison does not involve an MD5 hash, there is no path where an attacker‑controlled MD5 value could be loosely compared. All reachable executions of line 15 evaluate a numeric row count, which is safe and cannot be subverted by type‑juggling.
3. (c) The Semgrep rule `php.lang.security.md5-loose-equality` looks for a pattern where a value produced by `md5()` is later compared with `==` (or `!=`). The analyzer mistakenly linked the earlier `md5($pass)` (line 9) to the `== 1` comparison on line 15, even though the two statements are unrelated. Hence the false positive.
