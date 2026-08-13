# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/low.php:14

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

Line 5 reads user‑controlled data from $_REQUEST['ip'] (source). The value is stored in $target and directly concatenated into a command string on line 14, which is passed to shell_exec (OS command sink). No validation, sanitisation (e.g., escapeshellarg) or encoding is applied. The script is unconditional except for the presence of the POST 'Submit' flag, so any unauthenticated client can trigger it. shell_exec runs the assembled string via the system shell, providing a shell command injection vector (command channel). Because there is no neutralisation, an attacker can inject metacharacters to control the shell, establishing a bypass path. No evidence is available about the deployment environment, so production scope remains unresolved. [policy:command_injection entailed]
