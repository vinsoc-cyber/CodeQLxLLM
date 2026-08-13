# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:14

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line (14) calls file_get_contents with a path built from the user‑controlled $_GET['id'] (lines 11‑13). file_get_contents treats its argument as a filesystem path, so it is a qualifying path‑access sink. The source is external (GET parameter), establishing attacker control. The value flows directly into the path argument without any sanitisation, thus the path is reachable and can contain traversal sequences (e.g., ".."), allowing escape from the intended directory. No validation or allow‑list is present, so the defense is bypassed. Reading arbitrary files can disclose sensitive source code, constituting a security‑relevant effect. The code belongs to DVWA, a deliberately vulnerable training application, indicating it is not used in production. [policy:path_access entailed]
