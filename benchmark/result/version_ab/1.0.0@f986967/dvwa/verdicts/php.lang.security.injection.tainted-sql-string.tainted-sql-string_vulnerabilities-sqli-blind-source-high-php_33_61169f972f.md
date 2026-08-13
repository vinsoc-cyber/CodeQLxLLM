# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli_blind/source/high.php:33

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The variable $id is assigned from $_COOKIE['id'] (line 5), an external user-controlled source. It is directly interpolated into an SQL string on line 33 without any sanitisation or type casting. The constructed query is then executed via $sqlite_db_connection->query($query) on line 35, which runs relational SQL. No framework or library protections (e.g., prepared statements) are employed. The code path is reachable whenever the 'id' cookie is set, which any client can supply, so the attacker does not need prior authentication. Consequently, an attacker can inject arbitrary SQL, potentially bypassing the existence check or extracting data, representing a classic SQL injection vulnerability. The weakest link is the absence of any input validation or parameterisation before reaching the SQL execution sink. [policy:sql_injection entailed]
