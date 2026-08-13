# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/high.php:22

**Verdict:** FP · **Confidence:** High (0.0) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line (22) performs a loose equality `==` but compares the integer result of `mysqli_num_rows($result)` with the literal `1`; neither operand is an MD5 hash or other secret value, so `sink_binding` is NOT_PRESENT. Both operands are public (a row count and a constant), so `secret_operand` is NO_SECRET. The outcome of this comparison decides whether the login is considered successful (lines 22‑30), thus it gates authentication – a security decision, yielding `bypass_consequence` = SECURITY_DECISION. The code snippet provides no indication of the deployment environment, so `production_scope` cannot be resolved and is marked UNKNOWN. No additional evidence is required. [policy:loose_equality false_positive: sink_binding=NOT_PRESENT]
