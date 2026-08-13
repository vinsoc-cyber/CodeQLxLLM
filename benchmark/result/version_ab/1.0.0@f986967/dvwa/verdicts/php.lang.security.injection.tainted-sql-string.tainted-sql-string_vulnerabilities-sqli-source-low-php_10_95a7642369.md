# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['id'] (line 5, visible in the slice) and assigns it to $id. This value is interpolated directly into a SQL string on line 10 (MySQL case) and line 31 (SQLite case) without any escaping, validation, or parameterisation. The constructed query string is then passed to mysqli_query (line 11) or SQLite3::query (line 34), which execute the statement against a relational database, confirming a qualifying relational SQL sink. No sanitisation function (e.g., mysqli_real_escape_string) or prepared‑statement usage is present, so the attacker‑controlled value reaches the SQL text unfiltered, establishing a bypass path. The file resides in a directory named "vulnerabilities/sqli/source/low.php", suggesting a demonstration or test example rather than production code, so the production scope cannot be determined from the snippet. [policy:sql_injection entailed]
