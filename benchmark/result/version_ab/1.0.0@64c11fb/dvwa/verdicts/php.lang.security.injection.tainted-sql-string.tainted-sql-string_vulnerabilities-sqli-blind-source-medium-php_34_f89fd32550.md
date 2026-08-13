# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/medium.php:34

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The user‑controlled value $id originates from $_POST['id'] (line 5) and flows directly into the SQL string on line 34 without any sanitization in the SQLITE branch. The resulting string is executed via $sqlite_db_connection->query($query) (line 36), which is a relational SQL sink. No automatic parameterization or escaping is applied by the SQLite driver, and the code lacks any validation or escaping for this path, providing a bypass. The source is external user input, the flow reaches the sink, and the interpolated value becomes part of the SQL text, so the weakest link is the missing sanitization/parameterization in the SQLITE case. [policy:sql_injection entailed]
