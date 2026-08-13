# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5) and stores it in $target. It then applies a simple blacklist removal of '&&' and ';' via str_replace (line 14), which does not eliminate other shell metacharacters. The resulting $target is concatenated into a command string passed to shell_exec (line 23), which invokes the system shell. No framework or library sanitization is present. Any visitor can trigger the code by submitting the form, so the attacker is unauthenticated. This enables command injection (RCE) and possible DoS. The weakest link is the inadequate sanitization (blacklist) that fails to neutralize all dangerous characters, allowing command control. [policy:command_injection entailed]
