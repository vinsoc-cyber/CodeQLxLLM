# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source.php:63

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 2

## Reasoning

Line 13 assigns $_GET['security'] to $security, a remote attacker‑controlled value. Line 63 builds a filesystem path using that variable and passes it to file_get_contents, which reads a file from the server – a qualifying path access sink. The attacker‑controlled value reaches the sink without any sanitisation, allowing path traversal or absolute‑path manipulation, so an escape is possible and no defense is observed. The retrieved file content is later displayed with highlight_string (line 89), constituting a security‑relevant effect (information disclosure). The snippet does not indicate whether it runs in production or a test environment, so the scope is marked UNKNOWN. [policy:path_access entailed]
