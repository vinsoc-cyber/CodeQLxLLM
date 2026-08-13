# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/api/src/HealthController.php:88

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads raw HTTP request body (php://input) and decodes JSON (line 84). It extracts the 'target' field (line 86) without any validation or sanitization. This value is concatenated into a command string passed to exec() on line 88, which invokes the system shell. Therefore the attacker‑controlled data reaches a qualifying OS command sink, the command is built as a plain string, and no neutralization is applied, allowing command‑control injection. No framework or library protections are evident, and the method appears to be publicly accessible, implying unauthenticated access. The weakest link is the lack of input validation/escaping before the exec call. [policy:command_injection entailed]
