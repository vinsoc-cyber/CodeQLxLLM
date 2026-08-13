# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5) and concatenates it directly into a string passed to shell_exec (line 10 and line 14). No validation, sanitization, or escaping is performed. shell_exec launches a shell command, so the sink is a qualifying OS command sink. The attacker‑controlled value reaches the sink, forming a command string that the shell interprets, giving a clear command‑injection channel. Because there is no neutralization, an attacker can inject shell metacharacters (e.g., ';', '&', '`') to execute arbitrary commands, leading to remote code execution with the web‑server's privileges. The code is reachable by any POST request containing a 'Submit' field, implying unauthenticated access. The production scope cannot be inferred from the snippet, thus marked UNKNOWN. [policy:command_injection entailed]
