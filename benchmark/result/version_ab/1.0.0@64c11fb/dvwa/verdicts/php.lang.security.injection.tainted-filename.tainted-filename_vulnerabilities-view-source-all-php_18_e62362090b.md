# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:18

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line (18) calls file_get_contents with a path built from the user‑controlled variable $id (sourced from $_GET['id'] on line 12). This is a filesystem‑access sink, so sink_binding is QUALIFYING_PATH_ACCESS_SINK. The external source is proven, giving attacker_control = PROVEN. The value flows directly to the sink, so flow_to_path = REACHES. Because the path concatenates $id without any sanitisation, an attacker can inject '../' or absolute paths, leading to path traversal – ESCAPE_PATH_FOUND. No validation or allow‑list is visible, so defense_coverage = BYPASS_PATH_FOUND. Reading arbitrary files can disclose sensitive content, thus SECURITY_RELEVANT_EFFECT. The file belongs to DVWA, a deliberately vulnerable educational application, indicating it is example/development code, not production. [policy:path_access entailed]
