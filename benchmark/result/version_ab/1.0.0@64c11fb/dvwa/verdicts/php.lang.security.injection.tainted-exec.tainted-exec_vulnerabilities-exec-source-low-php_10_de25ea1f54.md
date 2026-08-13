# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/low.php:10

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5) and concatenates it directly into a string passed to shell_exec (line 10 for Windows, line 14 for *nix). No validation, sanitization, or escaping is performed. shell_exec launches a shell command, so the sink is an OS command execution. The attacker‑controlled value reaches the sink via simple string concatenation, establishing a shell command text path. Because there is no neutralization, an attacker can inject command separators or other metacharacters, giving command‑control capability. No surrounding framework or library provides automatic protection, and the code is reachable simply by submitting a POST request with the 'Submit' field, implying unauthenticated access. The impact is remote code execution (RCE) with the privileges of the PHP process. The weakest link is the lack of any sanitization before the shell_exec call. [policy:command_injection entailed]
