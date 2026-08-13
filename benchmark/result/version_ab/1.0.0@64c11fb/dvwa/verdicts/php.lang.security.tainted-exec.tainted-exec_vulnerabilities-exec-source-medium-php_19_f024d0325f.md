# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5) and stores it in $target. It then applies a blacklist that only strips '&&' and ';' (lines 9‑11) via str_replace (line 14). The resulting $target is concatenated into a command string passed to shell_exec (line 19 for Windows, line 23 for *nix). shell_exec launches a shell command, so the sink is an OS command execution. The attacker‑controlled value reaches the sink (flow REACHES) and is incorporated as plain text (command_channel = SHELL_COMMAND_TEXT_PATH_FOUND). Because the sanitization removes only a tiny subset of dangerous characters, an attacker can inject other shell metacharacters (e.g., '|', '`', '$()', newline) that are not filtered, providing a bypass path for command injection; thus neutralization_coverage is BYPASS_PATH_FOUND. No framework‑level escaping or validation is present, and the code is reachable by any request that sets the 'Submit' POST field, implying unauthenticated access. The impact of successful injection is remote code execution with the web‑server’s privileges. The production scope cannot be determined from the snippet. [policy:command_injection entailed]
