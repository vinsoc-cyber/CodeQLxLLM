# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5) into $target, then applies a blacklist via str_replace (lines 8‑21). The sanitized $target is concatenated into a command string passed to shell_exec (line 30) which invokes the system shell, satisfying the definition of an OS command sink. The blacklist does not cover all shell metacharacters (e.g., plain '|' , newline, '&' variants, etc.), so an attacker can craft input that survives the replacement and inject additional commands, giving a bypass path. Consequently, the command channel is a raw shell command string and neutralization coverage is insufficient. The file appears to be an example/demonstration under a 'vulnerabilities' directory, so the production scope cannot be determined from the snippet. [policy:command_injection entailed]
