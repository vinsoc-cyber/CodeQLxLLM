# php.lang.security.exec-use.exec-use @ vulnerabilities/api/src/HealthController.php:88

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

Line 84 reads the raw HTTP request body via `file_get_contents('php://input')`, which is attacker‑controlled network data. The value is decoded into an array (line 84) and, if the key `target` exists (line 85), it is assigned to `$target` (line 86). No validation, sanitization or escaping is performed before `$target` is concatenated into the command string passed to `exec` on line 88 (`exec ("ping -c 4 " . $target, $output, $ret_var);`). `exec` invokes the system shell, so the concatenated string is interpreted as a shell command, establishing a shell‑command text path. Because there is no neutralization such as `escapeshellarg` or an allow‑list, an attacker can inject shell metacharacters (e.g., `; rm -rf /`). The code runs in a controller with no visible authentication checks, so it is reachable by unauthenticated callers. The impact is remote code execution with the privileges of the PHP process. The weakest link is the absence of any input validation or escaping before the OS command execution. [policy:command_injection entailed]
