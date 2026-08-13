# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/medium.php:23

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5) and stores it in $target. It then applies a blacklist that only strips '&&' and ';' (line 14) – this does not neutralize other shell metacharacters. The resulting $target is concatenated into a command string passed to shell_exec (line 23 for *nix, line 19 for Windows), which launches a shell command. No framework or library sanitization is applied, and the code is reachable whenever a POST request with a 'Submit' field is sent, requiring no authentication. Consequently an attacker can inject additional shell commands, leading to remote code execution. The weakest link is the inadequate sanitization/absence of proper escaping (e.g., escapeshellarg), allowing command‑injection bypass. [policy:command_injection entailed]
