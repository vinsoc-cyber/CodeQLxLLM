# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/low.php:32

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_GET['id'] (line 5) and directly interpolates it into a SQL string (lines 11 and 32). The resulting string is passed unchanged to mysqli_query (line 13) or SQLite3::query (line 34), which execute the raw SQL. No validation, escaping, or prepared‑statement binding is performed. The code is reachable without authentication (only a Submit GET parameter is required). Consequently, an attacker can inject arbitrary SQL, leading to data disclosure or further exploitation. The weakest link is the absence of any sanitization or parameterization before the SQL sink. [policy:sql_injection entailed]
