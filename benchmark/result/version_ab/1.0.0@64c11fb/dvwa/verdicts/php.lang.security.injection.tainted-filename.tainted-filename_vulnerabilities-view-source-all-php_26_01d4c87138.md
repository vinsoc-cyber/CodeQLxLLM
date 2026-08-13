# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:26

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

The snippet shows that a GET parameter (lines checking $_GET) is assigned to $id and then interpolated directly into a file path used by file_get_contents, which reads files from the filesystem. No validation or sanitization is performed, allowing path traversal. This constitutes a qualifying path-access sink with attacker‑controlled input, no defenses, and a security‑relevant effect (disclosure of arbitrary files). The code belongs to DVWA, an intentionally vulnerable test application, indicating a test‑only production scope. [policy:path_access entailed]
