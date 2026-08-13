# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The user‑controlled value from $_REQUEST['ip'] (line 5) flows through a weak blacklist (lines 9‑14) and is concatenated into a string passed to shell_exec (line 23), which is a qualifying OS command sink. The blacklist does not remove all shell metacharacters, so an attacker can inject command control sequences, establishing a bypass path. No framework‑level sanitisation or authentication is present, making the code exploitable for remote code execution. [policy:command_injection entailed]
