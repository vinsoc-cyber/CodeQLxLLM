# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/api/src/HealthController.php:88

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads raw HTTP request body (php://input) into $input (line 84), extracts $target when the 'target' key exists (line 86), and concatenates it directly into an exec command string (line 88). No validation, sanitization, or escaping is applied before the exec call. Therefore user‑controlled data reaches an OS command sink, the command is built as a plain shell string, and the attacker can inject shell metacharacters, leading to remote code execution. No automatic framework protections are evident, and the privilege level required to reach this endpoint is not visible, so production scope remains unknown. [policy:command_injection entailed]
