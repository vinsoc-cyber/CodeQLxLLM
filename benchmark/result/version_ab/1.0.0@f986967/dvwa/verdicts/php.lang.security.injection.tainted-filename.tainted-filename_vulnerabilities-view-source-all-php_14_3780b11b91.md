# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:14

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line (14) calls file_get_contents with a path built from the user‑controlled GET parameter \$id (lines 11‑12). This makes the sink a filesystem‑path access (QUALIFYING_PATH_ACCESS_SINK). Because \$id originates from $_GET, attacker control is PROVEN and the value reaches the path argument (REACHES). The interpolated path "./{$id}/source/low.php" allows directory‑traversal via '..' or absolute segments, so path escape is ESCAPE_PATH_FOUND. No validation or sanitization of \$id is visible, therefore the defense is bypassed (BYPASS_PATH_FOUND). Reading arbitrary files can disclose source code, constituting a security‑relevant effect (SECURITY_RELEVANT_EFFECT). The file belongs to DVWA, an intentionally vulnerable educational app, indicating the code is not intended for production (TEST_ONLY). [policy:path_access entailed]
