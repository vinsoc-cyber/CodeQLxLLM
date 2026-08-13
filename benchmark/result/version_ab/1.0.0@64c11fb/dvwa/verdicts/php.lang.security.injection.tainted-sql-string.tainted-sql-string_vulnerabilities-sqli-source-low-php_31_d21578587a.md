# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli/source/low.php:31

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['id'] (line 5) into $id, interpolates it directly into a SQL string (line 31) and executes the statement via $sqlite_db_connection->query (line 34) (or mysqli_query in the MySQL branch). No sanitization, escaping, or prepared‑statement usage is visible, so the attacker‑controlled value reaches a relational SQL sink as raw text. The file resides in a "vulnerabilities/sqli/source" directory, indicating it is an example or test snippet rather than production code. [policy:sql_injection entailed]
