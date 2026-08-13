# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The provided slice (L1) shows that user‑controlled input from $_REQUEST['ip'] is read (line 5), blacklisted via str_replace (lines 8‑18, applied at line 21), and concatenated into a string passed to shell_exec (line 30). shell_exec executes a command via the system shell, satisfying QUALIFYING_OS_COMMAND_SINK. The source is external request data, establishing PROVEN attacker control. The data flow from the source through the transformation to the sink is present, so REACHES. Because the value is inserted into a command string that the shell parses, the channel is SHELL_COMMAND_TEXT_PATH_FOUND. The blacklist does not cover all shell metacharacters (e.g., newline, plain '|'), so the sanitization is insufficient and a bypass exists, giving BYPASS_PATH_FOUND. No framework‑level protections are evident, and the code can be triggered by any POST request containing the 'Submit' field, implying unauthenticated access. The overall production scope cannot be inferred from the snippet, thus UNKNOWN. [policy:command_injection entailed]
