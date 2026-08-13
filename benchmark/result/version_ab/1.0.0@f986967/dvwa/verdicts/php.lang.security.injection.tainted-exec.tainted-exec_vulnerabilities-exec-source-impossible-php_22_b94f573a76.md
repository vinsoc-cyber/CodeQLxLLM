# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/impossible.php:22

**Verdict:** FP · **Confidence:** High (0.0) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 8). It strips slashes (line 9), splits on '.', and validates that each octet is numeric and that exactly four parts exist (line 15). The validated octets are recombined into a dotted string (line 17). This string is concatenated into a command passed to shell_exec on line 22 (Windows) or line 26 (Unix), which executes a ping. Because the only possible values after validation consist solely of digits and dots, no shell metacharacters can be introduced, preventing command‑control injection. The sink is a classic OS‑command execution function, and the attacker‑controlled value clearly reaches it. No evidence is present about the environment (production vs test), so the scope is marked UNKNOWN. [policy:command_injection false_positive: command_channel=SHELL_COMMAND_TEXT_PATH_FOUND, neutralization_coverage=ALL_REACHING_PATHS]
