# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/brute/source/low.php:12

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads $_GET['username'] and $_GET['password'] (lines 5 and 8) which are attacker‑controlled inputs (source). The password is hashed with md5 (line 9) but the hash remains attacker‑controlled. Both $user and $pass are interpolated directly into a SQL string on line 12, creating a manually‑constructed query (sink). The query is then executed with mysqli_query on line 13, a relational SQL execution function. No escaping, prepared statements, or other sanitisation is applied before the interpolation, so the attacker‑controlled data reaches the SQL text unchanged. The surrounding framework provides no automatic protection for mysqli_query. The code is reachable by any unauthenticated GET request containing the 'Login' parameter, allowing an attacker to trigger the path. Consequently the vulnerability impact includes authentication bypass and potential data extraction/modification. The weakest link is the lack of any sanitisation/parameterisation for $user (and $pass). [policy:sql_injection entailed]
