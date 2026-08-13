# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/view_source.php:68

**Verdict:** TP · **Confidence:** Low (0.62) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 6

## Reasoning

The flagged sink (line 68) uses attacker‑controlled values to construct a filename that is read without any checks, enabling arbitrary file read (information disclosure). This constitutes a concrete exploitable consequence.

## Answers

1. 1. The variables $id and $security are ultimately derived from request parameters (typical in DVWA view_source.php) and are therefore attacker‑controlled.
2. 2. Data flow: $id / $security (source – request) → interpolated into the file path at line 63 (for the .php source) and line 68 (for the .js source) → passed to @file_get_contents (sink at line 68). No sanitisation occurs between source and sink.
3. 3. No validation, sanitisation, or encoding of $id or $security is visible before they are used in the file path.
4. 4. The sink is the call to @file_get_contents on line 68, which reads a file whose name is built from attacker‑controlled input.
5. 5. No framework or library‑provided automatic path sanitisation is present.
6. 6. The code is reachable by any user who can request view_source.php with arbitrary query parameters (no authentication guard is shown).
7. 7. An attacker can perform directory‑traversal via $id or $security to read arbitrary files on the server, leading to information disclosure (e.g., /etc/passwd) or exposure of other source files.
8. 8. The weakest link is the lack of any validation or sanitisation of $id/$security before they are concatenated into a file path (lines 63‑68).
