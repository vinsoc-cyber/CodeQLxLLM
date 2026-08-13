# php.lang.security.injection.tainted-filename.tainted-filename @ instructions.php:26

**Verdict:** FP · **Confidence:** High (0.93) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

User input is strictly limited to a predefined set of keys before being used as a filename, so the file read operation cannot be abused to access arbitrary files or remote resources; the reported tainted‑filename risk is not exploitable.

## Data flow

source (line 20) → whitelist check (line 21) → fallback (line 22) → $readFile assignment (line 24) → sink file_get_contents (line 26)

## Answers

1. 1. Source: user‑controlled HTTP GET parameter `doc` accessed via `$_GET['doc']` on line 20.
2. 2. Data flow: line 20 assigns `$_GET['doc']` to `$selectedDocId`; line 21 checks `array_key_exists($selectedDocId, $docs)`; line 22 may overwrite it with `'readme'`; line 24 assigns `$readFile = $docs[$selectedDocId]['file'];`; line 26 uses `$readFile` in `file_get_contents()`.
3. 3. Validation: the whitelist check on line 21 (and fallback on line 22) ensures `$selectedDocId` can only be one of the keys defined in `$docs` (lines 13‑18). Consequently `$readFile` can only be one of the four hard‑coded filenames (`README.md`, `docs/pdf.html`, `CHANGELOG.md`, `COPYING.txt`). This is sufficient to prevent arbitrary filename injection or SSRF.
4. 4. Sink: `file_get_contents()` on line 26 reads a file whose name is derived from `$readFile`.
5. 5. No additional framework protection is applied at the sink; safety relies on the whitelist validation performed earlier.
6. 6. No authentication checks are present in the snippet, so the path can be triggered by any unauthenticated user who supplies a `doc` query parameter.
7. 7. If the whitelist were absent, an attacker could achieve Local File Inclusion / information disclosure. With the whitelist in place, the attacker can only read the four intended documentation files, which does not constitute a security breach.
8. 8. The only defensive element is the whitelist validation on line 21, which is correctly implemented. There is no weak link; the defense chain is complete for this sink.
