# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled input from $_REQUEST['ip'] (line 5) into $target, applies a weak blacklist that only strips '&' and ';' (lines 8‑14), and then concatenates $target into a command string passed to shell_exec (line 23). shell_exec invokes the system shell, so the sink is an OS command. Because the source is a request variable, attacker control is proven. The data flows directly to the sink, establishing a reaching path. The concatenation creates a shell‑command text, therefore the command channel is a shell command string. The blacklist does not neutralize all shell metacharacters (e.g., '|', '`', newline), allowing an attacker to inject additional commands; thus neutralization coverage is bypassed. No information in the snippet indicates the environment (production vs test), so production_scope is unknown. [policy:command_injection entailed]
