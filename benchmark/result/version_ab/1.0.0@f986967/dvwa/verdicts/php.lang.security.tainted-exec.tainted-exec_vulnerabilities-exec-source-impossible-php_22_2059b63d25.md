# php.lang.security.tainted-exec.tainted-exec @ vulnerabilities/exec/source/impossible.php:22

**Verdict:** FP · **Confidence:** High (0.0) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line (22) is a direct call to shell_exec with a string that includes user‑controlled data ($target). The data originates from $_REQUEST['ip'] (external input) and is validated by is_numeric checks on each octet, ensuring only numeric characters reach the sink. Therefore the sink is an OS command execution, attacker control is proven, the flow reaches the sink, the channel is a concatenated command string interpreted by the shell, and the numeric validation covers all reaching paths. The production scope cannot be determined from the snippet. [policy:command_injection false_positive: command_channel=SHELL_COMMAND_TEXT_PATH_FOUND, neutralization_coverage=ALL_REACHING_PATHS]
