# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:26

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line (26) calls file_get_contents with a path built from the user‑controlled variable $id (assigned from $_GET['id'] on line 12). file_get_contents interprets its argument as a filesystem path, so it is a qualifying path‑access sink. The external GET parameter reaches the sink directly via string interpolation "./{$id}/source/impossible.php", establishing a REACHES data‑flow. Because the path is only prefixed with "./" and no validation or sanitisation is performed, an attacker can supply values such as "../.." to traverse directories, constituting an ESCAPE_PATH_FOUND and a BYPASS_PATH_FOUND (no whitelist, no realpath, no checks). Reading arbitrary files can disclose source code or other sensitive data, giving a SECURITY_RELEVANT_EFFECT. The code belongs to DVWA, a deliberately vulnerable training application, indicating it is not intended for production use; thus the production scope is classified as TEST_ONLY. [policy:path_access entailed]
