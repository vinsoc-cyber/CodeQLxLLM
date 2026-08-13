# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/csrf/test_credentials.php:23

**Verdict:** FP · **Confidence:** High (0.94) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line does not compare MD5 values; it safely compares two integers, so the rule's concern does not apply. The false positive arises from the rule's overly broad pattern matching. [second-opinion pass after 1-iter high-conf FP]

## Answers

1. a) Defense: The comparison on line 23 (`mysqli_num_rows( $result ) == 1`) is between two integers – the return value of `mysqli_num_rows()` (always an int) and the literal `1`. No MD5 hash participates, so there is no type‑juggling risk.
2. b) Coverage: Because `mysqli_num_rows()` cannot return a string and the literal is an integer, every possible execution path reaches a safe integer‑to‑integer comparison. The MD5 value computed on line 19 is never used in this comparison, so the defense applies to all reachable paths to the sink.
3. c) Rule behavior: The Semgrep rule `php.lang.security.md5-loose-equality.md5-loose-equality` looks for a loose equality operator (`==`) in a function that also contains an `md5()` call, without verifying that the operands of `==` are the MD5 values. It therefore mistakenly flags line 23, which is unrelated to the MD5 hash, resulting in a false positive.
