# php.lang.security.md5-loose-equality.md5-loose-equality @ vulnerabilities/brute/source/high.php:22

**Verdict:** FP · **Confidence:** High (0.92) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The flagged line (22) does not contain a comparison involving an MD5 value; the code only compares an integer literal (`== 1`). Therefore the pattern the rule looks for is not present, making the finding a false alarm.

## Data flow

source (line 13) → stripslashes (line 14) → mysqli_real_escape_string (line 15) → md5 hash (line 16) → SQL query interpolation (line 19)

## Answers

1. 1. The ultimate source of the data that could be involved in an MD5 comparison is the HTTP GET parameter `$_GET['password']` (line 13).
2. 2. Data flow for the password: line 13 (`$pass = $_GET['password'];`) → line 14 (`$pass = stripslashes($pass);`) → line 15 (`$pass = mysqli_real_escape_string(..., $pass);`) → line 16 (`$pass = md5($pass);`). The resulting MD5 hash is then interpolated into the SQL query on line 19 (`... password = '$pass'`).
3. 3. Sanitisation steps are applied before the MD5 hash (stripslashes and mysqli_real_escape_string). No validation or sanitisation is relevant to an MD5 equality comparison because no such comparison exists in the shown code.
4. 4. The only sink involving the MD5 value is the SQL query construction on line 19. No equality comparison (`==` or `===`) of an MD5 hash occurs anywhere in the snippet, including the flagged line 22 (`if( $result && mysqli_num_rows( $result ) == 1 )`).
5. 5. No framework or library provides automatic protection for MD5‑loose‑equality here. The code does escape the password before embedding it in the query, but that is unrelated to the MD5 comparison issue.
6. 6. The code path can be triggered by any unauthenticated user who supplies a `Login` parameter in the query string (line 3). No prior authentication is required.
7. 7. If an MD5 comparison were present and vulnerable, the impact could be authentication bypass. However, because no such comparison exists, there is no direct impact from the MD5‑loose‑equality class.
8. 8. The weakest link in the overall snippet is the use of string concatenation for the SQL query (line 19) instead of prepared statements, which could allow SQL injection despite escaping. Regarding the specific MD5‑loose‑equality rule, the weakest link is that the vulnerable pattern (MD5 compared with `==`) is simply absent, so there is no exploitable path.
