# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5) and concatenates it directly into a string that is handed to shell_exec() (line 14). No sanitisation or validation is performed, and there is no framework‑level protection. Consequently the attacker‑controlled value reaches a qualifying OS‑command sink via a shell‑command text path, and because no neutralisation is applied the path permits command‑control injection. The surrounding context provides no authentication guard, making the vulnerability exploitable by unauthenticated users. Production scope cannot be derived from the snippet, so it is marked UNKNOWN. [policy:command_injection entailed]
