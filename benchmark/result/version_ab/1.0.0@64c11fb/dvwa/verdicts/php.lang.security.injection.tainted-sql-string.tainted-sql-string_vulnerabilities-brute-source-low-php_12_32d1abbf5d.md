# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/brute/source/low.php:12

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads attacker‑controlled values from $_GET['username'] (line 5) and $_GET['password'] (line 8). The password is hashed with md5 (line 9) but the hash remains attacker‑controlled. Both values are interpolated directly into a SQL string on line 12, which is then executed by mysqli_query on line 13. No escaping, validation, or prepared‑statement binding is performed, so the attacker‑controlled data reaches the relational SQL sink as raw text. Consequently the sink is a qualifying relational SQL sink, the attacker control is proven, the flow reaches the sink, the query channel is via SQL text concatenation, and there is no neutralization covering the injected values, yielding a bypass path. The production scope cannot be inferred from the snippet. [policy:sql_injection entailed]
