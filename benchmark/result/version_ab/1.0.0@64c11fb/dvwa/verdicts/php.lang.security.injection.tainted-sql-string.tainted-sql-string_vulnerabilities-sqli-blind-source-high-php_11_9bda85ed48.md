# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/high.php:11

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads the attacker‑controlled value from $_COOKIE['id'] (line 5) and assigns it to $id. That value is interpolated directly into a SQL string on line 11 (and line 33 for SQLite) without any escaping, validation, or use of prepared statements. The resulting string is passed to mysqli_query (line 13) or SQLite's query method (line 35), which execute the raw SQL. No framework‑level protection is applied. Consequently the attacker‑controlled data reaches a relational SQL execution sink as plain text, with no neutralization, making the path exploitable. The weakest link is the lack of any sanitization or parameterization before the query is executed. [policy:sql_injection entailed]
