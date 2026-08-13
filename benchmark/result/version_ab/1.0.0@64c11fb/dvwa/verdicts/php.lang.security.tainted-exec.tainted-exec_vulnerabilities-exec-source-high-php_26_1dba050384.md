# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:26

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5) into $target, trims it, then applies a blacklist replacement (lines 8‑18) that removes a limited set of characters. The sanitized $target is concatenated into a command string passed to shell_exec (line 26 for Windows, line 30 for *nix). shell_exec invokes the system shell, so the sink is an OS command execution. No framework‑level escaping or validation is present, and the blacklist does not cover all shell metacharacters (e.g., newlines, backticks already removed but others remain), making the neutralization insufficient. The code is reachable without authentication checks, allowing any attacker who can submit a POST request with the 'ip' parameter to reach the sink. Consequently, an attacker can achieve command injection (RCE) with the privileges of the PHP process. The weakest link is the inadequate sanitization/blacklist before command construction. [policy:command_injection entailed]
