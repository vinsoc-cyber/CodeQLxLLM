# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:22

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line (22) calls file_get_contents with a path built from the user‑controlled variable $id (derived from $_GET['id'] on line 12). This makes the call a qualifying path‑access sink. The attacker‑controlled value reaches the sink directly, with no sanitisation or validation, allowing directory‑traversal (e.g., "../") to escape the intended directory. No defensive checks are visible, so the path is effectively bypassed. Reading arbitrary files and subsequently highlighting them can disclose server‑side source code, constituting a security‑relevant effect. The file belongs to DVWA, a deliberately vulnerable demonstration application, indicating it is not intended for production use. [policy:path_access entailed]
