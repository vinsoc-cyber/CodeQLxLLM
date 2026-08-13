# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_help.php:20

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line (20) calls file_get_contents with a path that includes the user‑controlled variable $id (sourced from $_GET['id'] on line 14). This path is then concatenated into an eval, causing execution of the file's contents. No sanitization or validation of $id is visible, allowing directory traversal (e.g., "../") to escape the intended directory. Consequently, the sink is a filesystem read (qualifying path access), the attacker controls the input, the flow reaches the sink, the path can be escaped, there is no defense, and the evaluated content can affect security. The production scope cannot be determined from the snippet alone. [policy:path_access entailed]
