# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/low.php:32

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads a GET parameter 'id' (line 5) into $id, then interpolates it directly into a SQL string on line 32. No validation, escaping, or prepared‑statement binding is performed before the string is passed to SQLite's query() method on line 34. This constitutes a reachable path from attacker‑controlled input to a relational SQL sink, with the attacker‑controlled value placed in the query text. The library does not provide automatic sanitisation for raw query strings, and there is no authentication guard before the block. Consequently the weakest link is the lack of any sanitisation/parameterisation before the query execution. [policy:sql_injection entailed]
