# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

Line 5 assigns $target from $_REQUEST['ip'], an external request parameter (attacker-controlled). This value is concatenated directly into a string passed to shell_exec on lines 10 and 14, launching a system command (OS command sink). No validation, sanitization, or escaping is performed before the call, so the attacker can inject shell metacharacters, providing a bypass path. The code runs conditionally on a POST with a 'Submit' field but has no authentication checks, implying unauthenticated access. The impact is remote code execution. The weakest link is the lack of any sanitization before the shell_exec call. [policy:command_injection entailed]
