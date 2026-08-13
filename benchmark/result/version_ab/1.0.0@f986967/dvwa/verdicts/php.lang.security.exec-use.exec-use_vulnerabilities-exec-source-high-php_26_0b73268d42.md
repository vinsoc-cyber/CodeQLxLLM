# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/high.php:26

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled input from $_REQUEST['ip'] (line 5), trims it, then applies a blacklist via str_replace (lines 8‑21). The sanitized value $target is concatenated into a string passed to shell_exec (line 26 for Windows, line 30 for *nix). shell_exec invokes the system shell, so this is an OS command sink. Because the source is a request superglobal, attacker control is proven. The data flow from source to sink is clear through $target (lines 5 -> 21 -> 26/30), thus flow_to_sink is REACHES. The attacker‑controlled string becomes part of the command text, establishing a shell command injection vector (SHELL_COMMAND_TEXT_PATH_FOUND). The blacklist does not remove all dangerous characters (e.g., single pipe '|', newline, $(), etc.), so an attacker can bypass the sanitization and inject additional commands (e.g., "8.8.8.8|cat /etc/passwd"). Therefore neutralization coverage is insufficient, yielding BYPASS_PATH_FOUND. No information is provided about deployment context, so production_scope remains UNKNOWN. [policy:command_injection entailed]
