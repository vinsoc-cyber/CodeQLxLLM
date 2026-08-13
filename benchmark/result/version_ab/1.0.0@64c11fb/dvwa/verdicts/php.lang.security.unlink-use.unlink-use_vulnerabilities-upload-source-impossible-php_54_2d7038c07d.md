# php.lang.security.unlink-use.unlink-use @ vulnerabilities/upload/source/impossible.php:54

**Verdict:** FP · **Confidence:** High (0.0) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The flagged unlink call (line 54) receives $temp_file, which is built from a random filename plus an extension derived from the uploaded file name ($uploaded_name from $_FILES, a remote user input). The code validates the extension against a whitelist of 'jpg', 'jpeg', and 'png' (lines 26‑28), ensuring the attacker cannot inject path traversal characters. The random prefix (bin2hex(random_bytes(16))) guarantees the filename cannot collide with existing files. Consequently the path argument is confined to a safe temporary directory and cannot be manipulated to delete arbitrary files. Therefore the sink is a path‑access operation, the attacker does control part of the data, the data reaches the sink, but no path escape is possible and the existing validation covers all reachable paths, resulting in no security‑relevant effect. The production scope cannot be inferred from the snippet, so it is marked UNKNOWN. [policy:path_access false_positive: path_escape=CONFINED_ALL_PATHS]
