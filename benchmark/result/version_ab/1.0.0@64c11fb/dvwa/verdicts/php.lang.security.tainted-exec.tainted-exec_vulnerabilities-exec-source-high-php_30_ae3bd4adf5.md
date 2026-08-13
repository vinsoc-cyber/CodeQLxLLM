# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The script reads user‑controlled data from $_REQUEST['ip'] (line 5) and stores it in $target. It then applies a blacklist via str_replace (line 21) that removes a limited set of characters but leaves many shell metacharacters (e.g., plain '|', '>', newline) untouched, so the sanitization is insufficient. The resulting $target is concatenated into a command string passed to shell_exec on line 30, which invokes the system shell. This constitutes a qualifying OS command sink, the attacker‑controlled value reaches the sink, and the command is built as a plain text string, giving the attacker a path to inject shell control characters. Because the blacklist can be bypassed, neutralization coverage is not complete. No framework‑level protections are present, and the code is reachable without authentication, leading to potential remote code execution. The weakest link is the inadequate blacklist sanitization. [policy:command_injection entailed]
