# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/fi/source/high.php:7

**Verdict:** FP · **Confidence:** Low (0.45) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 6

## Reasoning

The flagged line only performs a validation check; no dangerous operation (file inclusion, network request, etc.) uses the tainted value in the provided code, so there is no exploitable consequence at the sink.

## Data flow

source (line 4) → validation (line 7) → (no sink visible)

## Answers

1. 1. Source: user‑controlled GET parameter `page` via `$_GET['page']` (line 4).
2. 2. Data flow: line 4 assigns to `$file`; line 7 checks `$file` with `fnmatch("file*", $file)` and `$file != "include.php"`. No further use of `$file` is visible.
3. 3. Validation on line 7 is the only check; it does not sanitize the value for safe file inclusion or remote requests, but no later use is shown.
4. 4. No sink (e.g., `include`, `require`, `file_get_contents`, `curl_exec`, etc.) appears in any of the provided code; the flagged line is merely a conditional check.
5. 5. No framework or library automatic protection is present.
6. 6. No authentication checks are shown, so the code could be reached by any requester supplying the `page` parameter.
7. 7. Because there is no observable sink, no concrete attacker‑controlled consequence can be demonstrated from the available code.
8. 8. The weakest link is the absence of a visible sink; however, without a sink the path cannot be exploited, so the issue is not a real vulnerability.
