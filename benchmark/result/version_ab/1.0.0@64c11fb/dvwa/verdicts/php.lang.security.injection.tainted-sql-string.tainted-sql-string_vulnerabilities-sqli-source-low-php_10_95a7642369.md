# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The snippet reads the user‑controlled value $_REQUEST['id'] (line 5) and interpolates it directly into a SQL string (line 10). That string is then executed via mysqli_query (line 11) for MySQL and SQLite3::query (line 34) for SQLite, both of which are relational SQL execution functions, establishing a qualifying SQL sink. No sanitization, escaping, or prepared‑statement usage is present, so the attacker‑controlled value reaches the SQL text unchanged, creating a bypass of any neutralization. All these observations are present in the provided code slice (evidence L1). The production environment context cannot be inferred from the snippet, so it remains UNRESOLVED. [policy:sql_injection entailed]
