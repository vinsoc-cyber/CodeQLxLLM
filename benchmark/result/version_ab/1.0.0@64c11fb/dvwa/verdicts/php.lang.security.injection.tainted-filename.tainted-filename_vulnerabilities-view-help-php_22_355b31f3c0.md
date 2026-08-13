# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_help.php:22

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line (22) calls file_get_contents with a path built from the constant DVWA_WEB_PAGE_TO_ROOT and the user‑controlled variables $id and $locale (derived from $_GET). This constitutes a filesystem‑path sink (QUALIFYING_PATH_ACCESS_SINK). Because $id and $locale originate from $_GET, attacker control is PROVEN and the data flow reaches the path argument (REACHES). No sanitisation or validation is performed, allowing directory traversal or arbitrary file selection (ESCAPE_PATH_FOUND) and there is no visible defense (BYPASS_PATH_FOUND). The retrieved file content is then passed to eval, leading to execution of attacker‑controlled PHP code, which is a security‑relevant effect. The code belongs to DVWA, a deliberately vulnerable test application, but the snippet itself does not contain explicit metadata about production use, so the production scope is marked UNKNOWN. [policy:path_access entailed]
