# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/bac/source/low.php:79

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

Line 79 builds an INSERT statement by interpolating {$current_user_id}, {$target_id}, and '{$ip}'. The $ip variable (line 77) is derived from $_SERVER['HTTP_X_FORWARDED_FOR'] or $_SERVER['REMOTE_ADDR'], both attacker‑controllable sources, and is inserted into the SQL string without any escaping or parameterisation. The statement is executed with mysqli_query on line 81, a relational SQL sink. Therefore attacker‑controlled data reaches the SQL text directly, no sanitisation is applied, and the code runs in a production‑like context (unknown from the snippet). [policy:sql_injection entailed]
