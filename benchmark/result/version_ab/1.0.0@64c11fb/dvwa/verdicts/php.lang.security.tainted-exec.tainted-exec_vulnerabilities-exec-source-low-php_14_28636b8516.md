# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5) and concatenates it directly into a string passed to shell_exec (line 14). No validation, sanitization (e.g., escapeshellarg) or whitelisting is performed. shell_exec launches a shell command, making this a qualifying OS command sink. The attacker‑controlled value reaches the sink, forming a command string that the shell will interpret, so the command channel is a shell‑command text path. Because there is no neutralization, a bypass path exists for command injection. The surrounding script contains no framework‑level protections and no authentication checks, so any unauthenticated requester can trigger the code. The impact can be remote code execution with the web‑server's privileges. The weakest link is the missing sanitization of $target before it is used in the shell command. [policy:command_injection entailed]
