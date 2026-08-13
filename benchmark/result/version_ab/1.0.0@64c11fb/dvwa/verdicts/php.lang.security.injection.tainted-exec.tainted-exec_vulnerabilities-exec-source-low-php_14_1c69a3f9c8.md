# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5) and concatenates it directly into a string passed to shell_exec on line 14 (and line 10 for Windows). No validation, sanitization, or escaping is performed. shell_exec launches a shell command, so the sink is a qualifying OS command sink. The attacker‑controlled value reaches the sink, forming part of the command text, which gives the attacker full command‑injection capability. Consequently, there is no neutralization coverage and the weakest link is the missing sanitization before the shell_exec call. The surrounding code provides no framework‑level protections or authentication checks, and the environment (production vs test) cannot be inferred from the snippet. [policy:command_injection entailed]
