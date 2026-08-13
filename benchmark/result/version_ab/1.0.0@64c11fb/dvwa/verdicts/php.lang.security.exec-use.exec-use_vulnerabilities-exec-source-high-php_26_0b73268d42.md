# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/high.php:26

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The provided slice (L1) shows that $target is taken from $_REQUEST['ip'] (user‑controlled), a blacklist replacement is applied, and the resulting string is concatenated into a command passed to shell_exec, which is a qualifying OS command sink. The blacklist does not cover all shell metacharacters, so command injection is possible. No additional sanitization, quoting, or framework protections are visible, and the authentication state is not indicated, leaving production scope unknown. [policy:command_injection entailed]
