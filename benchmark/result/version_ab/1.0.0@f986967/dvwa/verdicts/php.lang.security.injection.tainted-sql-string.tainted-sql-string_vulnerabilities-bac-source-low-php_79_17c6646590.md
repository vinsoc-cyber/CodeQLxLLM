# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/bac/source/low.php:79

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line (79) builds an INSERT statement that includes the interpolated variables {$current_user_id}, {$target_id}, and '{$ip}'. The variable $ip is derived from $_SERVER['HTTP_X_FORWARDED_FOR'] or $_SERVER['REMOTE_ADDR'] (line 77), which is attacker‑controlled data (HTTP headers or IP address). This value is directly placed into the SQL string without any escaping or parameterisation and is later executed by mysqli_query (line 81), constituting a relational SQL sink. No sanitisation or prepared‑statement usage is present, so the attacker‑controlled value reaches the SQL text unfiltered, giving a bypass path. Other variables ($current_user_id, $target_id) are also injected but their provenance is not visible; at least one attacker‑controlled source ($ip) is sufficient to mark the flow as reaching the sink. The code appears to be example/development code, so production_scope is set to UNKNOWN. [policy:sql_injection entailed]
