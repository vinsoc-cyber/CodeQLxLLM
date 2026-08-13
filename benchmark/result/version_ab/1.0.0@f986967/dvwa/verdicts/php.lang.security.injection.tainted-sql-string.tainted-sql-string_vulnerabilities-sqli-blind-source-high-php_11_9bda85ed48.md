# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/high.php:11

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads attacker‑controlled data from $_COOKIE['id'] (line 3‑5) and interpolates it directly into a raw SQL string (line 11 and line 33) that is later executed by mysqli_query / SQLite query (line 13, 35). No escaping, casting or prepared‑statement usage is present, so the data reaches a relational SQL sink unchecked, constituting a classic SQL injection vulnerability. No framework‑level mitigation is applied, and the path is reachable by any client that can set the cookie, leading to potential data breach or modification. [policy:sql_injection entailed]
