# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5, L1) and concatenates it directly into a string passed to shell_exec on line 10 (and line 14 for *nix). No validation, sanitization, or escaping (e.g., escapeshellarg) is performed. shell_exec is an OS command execution sink, so the data flow reaches a qualifying command sink. The attacker‑controlled value becomes part of the command text that the shell interprets, providing a classic command‑injection channel. Because there is no neutralization, an attacker can inject shell metacharacters (e.g., ';', '&', '`', '$(...)') to execute arbitrary commands, leading to remote code execution. The script is triggered simply by a POST with a 'Submit' field, with no authentication checks, meaning an unauthenticated attacker can reach the vulnerable path. The production vs test context cannot be inferred from the snippet, so it is marked UNKNOWN. [policy:command_injection entailed]
