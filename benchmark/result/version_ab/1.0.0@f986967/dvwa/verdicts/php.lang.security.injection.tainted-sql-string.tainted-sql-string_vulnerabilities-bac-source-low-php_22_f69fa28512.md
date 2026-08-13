# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/bac/source/low.php:22

**Verdict:** FP · **Confidence:** High (0.0) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The GET parameter flows to $id after a strict digit‑only regex and intval(). The integer is interpolated into a SELECT statement that is executed via mysqli_query. Because the value is guaranteed to be a pure integer, no SQL‑injection payload can influence the query syntax, satisfying neutralisation on all paths. The sink is a relational SQL call, the attacker control is proven, and the query text contains attacker data, but it is safely bounded. The code appears to be sample / test code (DVWA), so production scope is indeterminate. [policy:sql_injection false_positive: neutralization_coverage=ALL_REACHING_PATHS]
