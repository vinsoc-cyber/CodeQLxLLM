# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The code reads a value from $_REQUEST['ip'] (line 5) and stores it in $target. It then applies a blacklist replacement (lines 8‑21) that removes a limited set of characters but does not eliminate all shell metacharacters. The resulting $target is concatenated into a string passed to shell_exec (line 30), which executes a shell command. Therefore the sink is a qualifying OS command sink, the attacker‑controlled data reaches it, the command is built as a plain text string (shell command text path), and the sanitization can be bypassed, giving a bypass path. No framework‑level protections are evident, and the code appears to be reachable in a generic POST request, so the production scope cannot be determined from the snippet. [policy:command_injection entailed]
