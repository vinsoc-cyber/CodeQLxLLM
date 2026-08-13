# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/low.php:11

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The GET parameter 'id' (line 5) is assigned to $id and interpolated directly into a SQL string (lines 11 and 32). The resulting query is executed by mysqli_query (line 13) and SQLite::query (line 34) without any escaping, parameterisation, or validation. This constitutes a classic SQL injection vulnerability (CWE‑89). No framework‑level mitigation is present, and the code is reachable by any unauthenticated request that includes the Submit flag. [policy:sql_injection entailed]
