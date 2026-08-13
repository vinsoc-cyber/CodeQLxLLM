# php.lang.security.exec-use.exec-use @ vulnerabilities/api/src/HealthController.php:88

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads raw HTTP request body via `file_get_contents('php://input')` (line 84), decodes JSON, extracts the user‑controlled field `target` (lines 85‑86), and concatenates it directly into a command string passed to `exec` (line 88). No validation, sanitization, or escaping is performed. `exec` launches a shell command, so the sink is an OS command. The attacker‑controlled value reaches the command string, creating a shell‑command text path where metacharacters are interpreted, and there is no neutralization, giving a bypass path. The surrounding framework does not provide automatic protection for this call, and the method appears to be publicly reachable (no auth checks shown). Consequently the weakest link is the lack of input validation/escaping before the `exec` call. [policy:command_injection entailed]
