# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/high.php:30

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads user-controlled input from $_REQUEST['ip'] (line 5) into $target. It applies a blacklist via str_replace (lines 8‑18, applied at line 21) but does not eliminate all shell metacharacters (e.g., newline). The resulting $target is concatenated into a string passed to shell_exec on line 30 (or line 26 for Windows). shell_exec invokes the system shell, making the call a qualifying OS command sink. Because the source is an HTTP request variable, attacker_control is PROVEN. The variable $target reaches the sink, so flow_to_sink is REACHES. The value is injected directly into the command string, giving a SHELL_COMMAND_TEXT_PATH_FOUND channel. The blacklist is insufficient; a crafted value can inject a newline or other characters not stripped, providing a bypass, therefore neutralization_coverage is BYPASS_PATH_FOUND. No information about deployment environment is present, so production_scope remains UNRESOLVED. [policy:command_injection entailed]
