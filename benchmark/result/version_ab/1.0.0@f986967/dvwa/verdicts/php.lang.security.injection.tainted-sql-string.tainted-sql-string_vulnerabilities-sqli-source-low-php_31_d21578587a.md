# php.lang.security.injection.tainted-sql-string.tainted-sql-string @ vulnerabilities/sqli/source/low.php:31

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads the user‑controlled value `$_REQUEST['id']` into `$id` (line 5). That value is directly interpolated into a SQL string on line 31 (`$query = "SELECT … WHERE user_id = '$id';"`). The resulting query string is passed unchanged to SQLite (`$sqlite_db_connection->query($query)` on line 34) and, in the MySQL case, to `mysqli_query` on line 11, both of which execute raw relational SQL. No sanitisation, escaping, casting, or prepared‑statement binding is applied anywhere in the visible snippet. The script is gated only by `isset($_REQUEST['Submit'])`, so any remote user can trigger it without authentication. Consequently, an attacker can inject arbitrary SQL, leading to data exfiltration or manipulation. The weakest link is the lack of any input neutralisation before the query is executed. [policy:sql_injection entailed]
