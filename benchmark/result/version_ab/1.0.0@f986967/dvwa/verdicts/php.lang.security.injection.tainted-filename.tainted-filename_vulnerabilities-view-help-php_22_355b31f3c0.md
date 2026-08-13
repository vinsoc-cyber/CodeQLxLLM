# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_help.php:22

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line (22) calls file_get_contents with a path built from a constant base and user-controlled variables $id and $locale taken from $_GET (lines 11-16). This satisfies a qualifying path access sink, with proven attacker control over the path. The data flow reaches the sink directly, without sanitization, allowing path traversal (escape) and no defenses are visible, thus a bypass. The file contents are then fed to eval, leading to execution of attacker-controlled code, which is a security-relevant effect. The code belongs to DVWA, an intentionally vulnerable test application, so the scope is test-only. [policy:path_access entailed]
