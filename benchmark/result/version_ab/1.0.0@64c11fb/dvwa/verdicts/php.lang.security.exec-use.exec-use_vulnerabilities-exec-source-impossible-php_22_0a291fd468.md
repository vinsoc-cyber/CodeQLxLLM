# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/impossible.php:22

**Verdict:** FP · **Confidence:** High (0.0) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The user‑controlled value from $_REQUEST['ip'] (line 8) is validated only by is_numeric checks (line 15) and then concatenated into a string passed to shell_exec (line 22/26). The sink is a genuine OS command execution, the attacker controls the data, the data reaches the sink, and the command is built as a plain shell string, so a shell command text path exists. Because the numeric validation eliminates all shell metacharacters, there is no bypass path; all reaching paths are covered by the validation. No information about deployment environment is present, so production scope is unknown. [policy:command_injection false_positive: command_channel=SHELL_COMMAND_TEXT_PATH_FOUND, neutralization_coverage=ALL_REACHING_PATHS]
