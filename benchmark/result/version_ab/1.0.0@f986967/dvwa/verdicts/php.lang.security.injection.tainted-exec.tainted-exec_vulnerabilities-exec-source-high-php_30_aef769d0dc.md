# php.lang.security.injection.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user‑controlled data from $_REQUEST['ip'] (line 5) – a remote source, therefore attacker_control is PROVEN. The value is then passed through a blacklist str_replace (line 21) that removes a limited set of characters but leaves many shell metacharacters (e.g., newline, single '|', redirection symbols) untouched, so the sanitization is insufficient and a bypass exists, giving neutralization_coverage = BYPASS_PATH_FOUND. The sanitized (or not) value is concatenated into a string that is handed to shell_exec on line 30, which executes the string via the system shell; this is a qualifying OS command sink and the attacker value reaches it (flow_to_sink = REACHES) as plain command text (command_channel = SHELL_COMMAND_TEXT_PATH_FOUND). The file location provides no indication that it is production code, so production_scope remains UNKNOWN. [policy:command_injection entailed]
