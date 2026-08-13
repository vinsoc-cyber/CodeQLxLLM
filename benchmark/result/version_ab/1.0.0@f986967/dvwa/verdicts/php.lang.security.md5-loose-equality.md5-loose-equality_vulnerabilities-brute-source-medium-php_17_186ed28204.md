# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/medium.php:17

**Verdict:** FP · **Confidence:** High (0.0) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

Line 17 contains a loose '==' comparison (L1). Both operands are the integer row count returned by mysqli_num_rows and the literal 1, none of which are secret values, so secret_operand = NO_SECRET. The outcome of this comparison controls whether the login is considered successful, therefore it is a security decision. No information in the snippet indicates whether the code runs in production or test, so production_scope remains UNKNOWN. [policy:loose_equality false_positive: secret_operand=NO_SECRET]
