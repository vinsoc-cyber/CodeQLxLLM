# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The script reads user‑controlled data from $_REQUEST['ip'] (line 5) – a proven external source. The value is only passed through a blacklist that removes '&&' and ';' via str_replace (line 14), which does not neutralize many other shell metacharacters. The sanitized value is concatenated into a string that is handed to shell_exec (line 19 for Windows, line 23 for *nix). shell_exec invokes the system shell, so this is an OS command sink. Because the attacker‑controlled string becomes part of the command text, the command channel is a shell‑command‑text path. The blacklist does not prevent injection of characters such as '|', '`', '$()', newline, etc., therefore neutralization is insufficient and a bypass path exists. No framework or library protections are present, and the code is reachable without authentication checks, making the impact remote code execution. The weakest link is the inadequate sanitization (blacklist) before the command is executed. [policy:command_injection entailed]
