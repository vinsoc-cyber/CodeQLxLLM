# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/bac/source/medium.php:71

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code builds an INSERT statement on line 71 using interpolated variables {$current_user_id}, {$target_id}, and '{$ip}'. The $ip variable originates from $_SERVER['HTTP_X_FORWARDED_FOR'] or $_SERVER['REMOTE_ADDR'] (line 69), which are attacker‑controlled request headers. No escaping, validation, or prepared‑statement binding is applied before the string is passed to mysqli_query on line 73, so the attacker‑controlled value reaches a relational SQL sink as raw text. This satisfies the definition of a qualifying relational SQL sink, confirms attacker control, shows a reachable path, and demonstrates that the query text contains attacker data without any neutralization, leading to a bypass path. The production environment cannot be inferred from the snippet, so its scope is marked UNKNOWN. [policy:sql_injection entailed]
