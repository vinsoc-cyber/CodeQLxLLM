# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/low.php:11

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads $id directly from $_GET['id'] (line 5) – a remote attacker-controlled source. It then interpolates $id into a SQL string on line 11 (and line 32 for SQLite) without any validation, casting, or escaping. The resulting $query string is passed to mysqli_query (line 13) or SQLite's query method (line 34), which executes the raw SQL against a relational database, satisfying a qualifying relational SQL sink. No framework or library automatic protection is present because the code uses low‑level query functions rather than prepared statements. The code block is reachable to any user who can issue a GET request with the 'Submit' parameter, implying unauthenticated access. An attacker can inject arbitrary SQL, leading to data disclosure or manipulation. The weakest link is the lack of sanitization/parameterization before the sink. [policy:sql_injection entailed]
