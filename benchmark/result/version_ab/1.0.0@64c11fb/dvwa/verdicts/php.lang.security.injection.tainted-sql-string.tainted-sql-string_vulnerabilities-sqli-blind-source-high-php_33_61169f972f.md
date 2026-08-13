# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/high.php:33

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads the attacker‑controlled value from $_COOKIE['id'] (line 5) and assigns it to $id. The same variable is interpolated directly into a SQL string (lines 11 and 33) without any validation, escaping, or use of prepared statements. The resulting string is passed to mysqli_query (line 13) or SQLite's query method (line 35), which execute the statement against a relational database. No framework or library sanitization is applied. Consequently the attacker‑controlled data reaches a relational SQL sink as raw text, creating a classic SQL injection vector. The weakest link is the lack of any sanitization or parameterization before the interpolation. [policy:sql_injection entailed]
