# php.lang.security.eval-use.eval-use @ vulnerabilities/view_help.php:20

**Verdict:** TP · **Confidence:** High (0.91) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 4

## Reasoning

Attacker‑controlled GET parameters flow directly to an eval() of file contents without any visible sanitisation, giving an exploitable RCE vector for authenticated users.

## Data flow

$_GET['id'] (line 14) → $id (line 14) → file path in file_get_contents (line 20) → eval() (line 20)

## Answers

1. 1. The source is attacker‑controlled HTTP GET parameters: `$_GET['id']` (line 14) and `$_GET['locale']` (line 16).
2. 2. Data flow: `$_GET['id']` → `$id` (line 14) → interpolated into the file path in `file_get_contents( DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help/help.php" )` (line 20) → the file contents are concatenated into a string that is passed to `eval()` (line 20). The same flow exists for `$locale` in the else‑branch (line 22). No other transformations are visible.
3. 3. No validation, sanitisation, or encoding of `$id` or `$locale` is performed in the visible code. The only checks are `array_key_exists` (lines 11‑13), which merely confirm the parameters exist and do not restrict their content. The bodies of `dvwaPageStartup`, `dvwaPageNewGrab`, and `dvwaHelpHtmlEcho` are unavailable, so we cannot assert any hidden sanitisation.
4. 4. The sink is the `eval()` call on line 20 (and line 22). It executes PHP code read from a file whose path is built from attacker‑controlled input, creating an unchecked code‑execution point.
5. 5. No automatic framework protection for this `eval()` usage is evident. `dvwaPageStartup` enforces authentication but does not appear to sanitize the parameters.
6. 6. The script calls `dvwaPageStartup( array( 'authenticated' ) );` (line 6), so an attacker must be an authenticated DVWA user. No additional privilege checks are present.
7. 7. If an attacker can influence `$id`/`$locale`, they can cause arbitrary PHP code to be read and executed, resulting in Remote Code Execution (RCE) with the web‑server’s privileges.
8. 8. The weakest link is the absence of any visible validation or whitelisting of `$id` (and `$locale`) before they are incorporated into the file path that is later evaluated. This unchecked user input enables the exploit.
