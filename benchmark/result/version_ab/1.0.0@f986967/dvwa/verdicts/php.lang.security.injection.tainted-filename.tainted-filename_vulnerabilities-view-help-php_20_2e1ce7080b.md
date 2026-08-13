# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_help.php:20

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line (20) uses file_get_contents with a path built from a constant base and the user‑controlled variable $id (sourced from $_GET). This satisfies a path‑access sink (file read). The input is attacker‑controlled (remote GET parameter). The value flows directly into the path argument without any sanitization, so the flow reaches the sink. Because $id can contain directory‑traversal sequences (e.g., "../"), the attacker can escape the intended directory, constituting a path escape. No validation, whitelisting, or normalization is visible, so there is no defense coverage. The file contents are then fed to eval, meaning arbitrary PHP code can be executed, which is a security‑relevant effect. The code belongs to DVWA, a deliberately vulnerable training application, not intended for production use. [policy:path_access entailed]
