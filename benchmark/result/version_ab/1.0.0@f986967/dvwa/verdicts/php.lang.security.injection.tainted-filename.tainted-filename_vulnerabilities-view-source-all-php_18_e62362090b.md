# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source_all.php:18

**Verdict:** TP · **Confidence:** High (0.0) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged line (18) calls file_get_contents with a path built from the user‑controlled \$id (derived from $_GET['id'] on line 12). file_get_contents is a filesystem‑access sink, so sink_binding is QUALIFYING_PATH_ACCESS_SINK. Because \$id originates from an external request parameter, attacker_control is PROVEN. The value flows directly into the path argument, establishing flow_to_path as REACHES. The constructed path "./{$id}/source/medium.php" allows directory traversal (e.g., id='..') or other path manipulation, so path_escape is ESCAPE_PATH_FOUND. No validation, sanitization, or allow‑list check precedes the file read; the later switch statement occurs after the read, so defense_coverage is BYPASS_PATH_FOUND. Reading arbitrary files and later highlighting them can disclose file contents, yielding a SECURITY_RELEVANT_EFFECT. The script is part of DVWA (Damn Vulnerable Web Application), a teaching/demo platform, indicating the code is not intended for production—hence production_scope is TEST_ONLY. [policy:path_access entailed]
