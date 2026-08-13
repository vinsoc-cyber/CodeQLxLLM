# php.lang.security.exec-use.exec-use @ vulnerabilities/exec/source/medium.php:19

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The code reads user‑controlled input from $_REQUEST['ip'] (line 5 of the slice), applies a minimal blacklist that only removes "&&" and ";" (lines 9‑10) via str_replace (line 14), and then concatenates the result directly into a string passed to shell_exec (line 19). This constitutes a qualifying OS command sink, the attacker‑controlled value reaches the sink, the command is built as a plain shell command string, and the sanitisation is insufficient, providing a bypass path. No framework‑level protections or authentication checks are evident, so the vulnerability is exploitable. [policy:command_injection entailed]
