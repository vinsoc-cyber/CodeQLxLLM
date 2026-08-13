# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:22

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

Line 11 extracts $id directly from $_GET, a remote request source (PROVEN attacker control). The same $id is interpolated into the path argument of file_get_contents on line 22 (and similar lines), which is a filesystem‑read operation, thus a qualifying path‑access sink. The value flows unmodified from the source to the sink (REACHES). Because the path is built as "./{$id}/source/high.php", an attacker can supply path‑traversal components (e.g., "../..") to escape the intended directory, so an escape is possible (ESCAPE_PATH_FOUND). No validation, sanitisation, or allow‑list is applied before the call, giving a bypassable path (BYPASS_PATH_FOUND). The file contents are later highlighted and displayed, potentially disclosing arbitrary files (SECURITY_RELEVANT_EFFECT). The code belongs to DVWA, a deliberately vulnerable training application, indicating it is not production code (EXAMPLE_DEV). [policy:path_access entailed]
