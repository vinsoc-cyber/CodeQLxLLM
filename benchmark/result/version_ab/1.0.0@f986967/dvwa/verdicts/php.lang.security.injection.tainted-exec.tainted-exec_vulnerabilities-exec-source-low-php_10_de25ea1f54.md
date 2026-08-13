# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads attacker‑controlled input from $_REQUEST['ip'] (line 5) and concatenates it directly into a string passed to shell_exec() (line 10/14). No sanitisation or validation is performed, the call is a true OS command execution, and the attacker can inject shell metacharacters, yielding a reachable command‑injection RCE path. The snippet does not indicate any production‑only guards, so production_scope remains UNKNOWN. [policy:command_injection entailed]
