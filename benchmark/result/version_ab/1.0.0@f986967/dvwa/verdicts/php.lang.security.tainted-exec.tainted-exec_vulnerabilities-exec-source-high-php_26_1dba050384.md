# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:26

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5) into $target, applies a simple blacklist via str_replace (line 21) that does not cover all shell metacharacters (e.g., newline, '/' etc.). The resulting $target is concatenated directly into a command string passed to shell_exec on line 26 (Windows) or line 30 (Unix), which launches the command through the system shell. Therefore the sink is a qualifying OS command sink, the attacker‑controlled value reaches it, the command channel is a raw command‑text string, and the provided sanitization is insufficient, leaving a bypass path for command injection. No framework‑level protections are present, and the code is reachable by any requester submitting the form, giving unauthenticated attackers the ability to execute arbitrary commands (RCE). [policy:command_injection entailed]
