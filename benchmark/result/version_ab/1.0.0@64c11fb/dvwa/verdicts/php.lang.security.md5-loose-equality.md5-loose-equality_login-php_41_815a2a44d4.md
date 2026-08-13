# php.lang.security.md5-loose-equality.md5-loose-equality @ login.php:41

**Verdict:** FP · **Confidence:** High (0.94) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged `==` comparison does not involve an MD5 hash, so the loose‑equality issue cannot be exploited. The rule over‑approximates by linking any `==` after an `md5()` call, leading to a false positive. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. (a) No specific defense against a loose‑equality MD5 comparison is needed because the code never compares an MD5 hash with `==`. The only `==` operator appears on line 41: `if( $result && mysqli_num_rows( $result ) == 1 )`, which compares the integer row count to the literal `1`. No MD5 value participates in this comparison.
2. (b) Because there is **no** MD5‑value‑to‑MD5‑value comparison in any reachable path, the absence of a strict‑comparison (`===`) guard cannot be exploited. All execution paths that reach line 41 go through the query at line 40, but the result of that query is an integer row count, not an MD5 hash, so the potential type‑juggling issue the rule targets cannot arise.
3. (c) The Semgrep rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for a pattern where a value produced by `md5()` (or a variable that holds such a value) is later compared using the loose equality operator `==`. It likely matches the assignment on line 27 (`$pass = md5( $pass );`) and then any subsequent `==` comparison in the same function, without verifying that the compared operands are the MD5 hash. Since line 41 contains a `==` but does not involve `$pass`, the rule mistakenly flags it, resulting in a false positive.
