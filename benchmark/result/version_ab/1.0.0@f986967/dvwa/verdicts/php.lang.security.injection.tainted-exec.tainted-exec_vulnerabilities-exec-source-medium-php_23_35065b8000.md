# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled input from $_REQUEST['ip'] (L1:5), applies a simple blacklist that only strips '&&' and ';' (L1:9-14), and then concatenates the result into a string passed to shell_exec (L1:23). shell_exec invokes the system shell, so the value participates in a shell command text (SHELL_COMMAND_TEXT_PATH_FOUND). Because the sanitisation does not remove other shell metacharacters (e.g., '|', '`', '$(...)', newline), an attacker can craft input that injects additional commands, establishing a bypass path (BYPASS_PATH_FOUND). The surrounding context does not indicate any production environment, thus production_scope is set to UNKNOWN. [policy:command_injection entailed]
