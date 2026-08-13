# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source.php:63

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

Line 13 assigns $security directly from $_GET, proving attacker control. Line 63 passes a string containing {$security} to file_get_contents, a filesystem read function, confirming a path‑access sink. The attacker‑controlled value reaches the path argument, and because no validation or sanitisation is performed, directory‑traversal payloads (e.g., '../') can escape the intended directory, indicating path escape and lack of defense. The file contents are later echoed to the page, exposing potential sensitive data, which is a security‑relevant effect. The surrounding context does not provide information about whether this code runs in production, so that slot remains unresolved. [policy:path_access entailed]
