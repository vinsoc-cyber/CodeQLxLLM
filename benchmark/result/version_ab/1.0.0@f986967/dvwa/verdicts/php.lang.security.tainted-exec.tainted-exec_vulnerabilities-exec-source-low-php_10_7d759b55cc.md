# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5) into $target, concatenates it directly into a command string passed to shell_exec on line 10 (Windows) or line 14 (Unix). No validation, sanitization (e.g., escapeshellarg) or whitelisting is performed. shell_exec is an OS command execution sink, so the attacker‑controlled value reaches a qualifying command via string concatenation, giving a shell‑command text path. Because there is no neutralization, an attacker can inject shell metacharacters (e.g., ';', '&') to achieve command injection, establishing a bypass path. The surrounding code provides no framework‑level protection or authentication checks, indicating the path is reachable by unauthenticated users. The file location does not reveal the deployment environment, so production scope is unknown. [policy:command_injection entailed]
