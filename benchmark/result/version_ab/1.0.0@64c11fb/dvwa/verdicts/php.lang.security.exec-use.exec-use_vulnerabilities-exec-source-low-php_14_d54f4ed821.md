# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5) and concatenates it directly into a string passed to shell_exec (line 14). No validation, sanitization, or escaping is performed. shell_exec launches a shell command, so the sink is an OS command execution. The attacker‑controlled value reaches the sink, forming a command string that the shell interprets, providing a command‑injection channel. Because there is no neutralization, an attacker can inject shell metacharacters, yielding a bypass path. No framework or library protections are present, and the code is reachable by any POST request (no auth checks). Hence the weakest link is the missing sanitization before the shell_exec call. [policy:command_injection entailed]
