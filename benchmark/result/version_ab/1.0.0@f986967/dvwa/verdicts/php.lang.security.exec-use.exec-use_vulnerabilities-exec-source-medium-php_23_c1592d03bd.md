# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled input from $_REQUEST['ip'] (line 5) and assigns it to $target (L1). It then attempts to sanitize by removing only '&&' and ';' via str_replace (line 14), which is a weak blacklist. The sanitized $target is concatenated into a command string passed to shell_exec on line 23, which runs the command through the system shell, constituting an OS command sink. Because the input reaches the shell command string with insufficient neutralization, an attacker can inject additional shell metacharacters (e.g., '|', '`', '\n') that were not stripped, giving a bypass path. Hence the command channel is a shell‑command‑text path, and neutralization coverage is bypassed. The production scope cannot be inferred from the snippet, so it is marked UNKNOWN. [policy:command_injection entailed]
