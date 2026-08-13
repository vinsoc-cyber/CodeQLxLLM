# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code takes attacker‑controlled input from $_REQUEST['ip'] (L1: line 5) and concatenates it directly into a string passed to shell_exec (L1: lines 10 and 14). No sanitisation or validation is performed, and shell_exec executes the string via the system shell, fulfilling the definition of an OS‑command sink. Consequently the attacker can inject shell meta‑characters, leading to command injection (RCE). The only missing information is whether the file is used in production; this cannot be inferred from the snippet, so production_scope remains UNRESOLVED. [policy:command_injection entailed]
