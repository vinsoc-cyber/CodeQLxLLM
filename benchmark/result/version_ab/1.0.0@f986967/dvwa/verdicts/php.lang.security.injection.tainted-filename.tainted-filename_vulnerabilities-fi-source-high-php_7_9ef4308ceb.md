# php.lang.security.injection.tainted-filename.tainted-filename @ vulnerabilities/fi/source/high.php:7

**Verdict:** FP · **Confidence:** Low (0.45) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 6

## Reasoning

The flagged line only performs a whitelist check; the snippet does not contain any operation that actually uses the user‑controlled filename, so there is no exploitable consequence demonstrated. Without a visible sink, the finding does not represent a real vulnerability in the shown code.

## Answers

1. 1. Source: external HTTP GET parameter `page` via `$_GET['page']` on line 4.
2. 2. Data flow: line 4 assigns the GET value to `$file`; line 7 performs a whitelist check (`fnmatch('file*', $file)` and `$file != "include.php"`). No further propagation is visible.
3. 3. Validation: the whitelist test on line 7 is the only defensive measure; it limits `$file` to strings beginning with "file" or the exact string "include.php". No sanitization or encoding beyond this check is shown.
4. 4. Sink: no file‑system, network, or execution operation that consumes `$file` is present in the provided snippets. The downstream function that might use `$file` (e.g., `include`, `require`, `file_get_contents`) was not available.
5. 5. No framework‑level automatic protections are evident in the visible code.
6. 6. The code can be triggered by any client that can supply a `page` query parameter, i.e., an unauthenticated attacker could reach it.
7. 7. Because the variable is never used in a dangerous operation within the visible context, no concrete impact (RCE, data exfiltration, etc.) can be demonstrated.
8. 8. The weakest link is the absence of a visible sink; however, without seeing a downstream use of `$file`, we cannot assess whether the whitelist check is sufficient.
