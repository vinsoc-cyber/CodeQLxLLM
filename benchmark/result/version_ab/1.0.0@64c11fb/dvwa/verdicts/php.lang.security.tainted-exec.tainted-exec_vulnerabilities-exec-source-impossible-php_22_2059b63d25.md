# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/impossible.php:22

**Verdict:** FP · **Confidence:** High (0.0) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The user‑controlled value comes from $_REQUEST['ip'] (line 8) and is passed through stripslashes, explode, numeric checks, and reconstruction before being concatenated into a string given to shell_exec on line 22 (or 26). The numeric validation ensures only digits, optional sign, decimal point, or exponent characters reach the command, preventing shell metacharacters. The sink is a shell_exec call, which runs a command via the system shell, so it qualifies as an OS command sink. The data flow from the request to the sink is direct and reachable, establishing attacker control. The command is built as a plain string, thus the command channel is a shell‑command‑text path. No escaping function is used, but the numeric validation effectively neutralizes injection, covering all reaching paths. No information about deployment environment is present, so production scope is unknown. [policy:command_injection false_positive: command_channel=SHELL_COMMAND_TEXT_PATH_FOUND, neutralization_coverage=ALL_REACHING_PATHS]
