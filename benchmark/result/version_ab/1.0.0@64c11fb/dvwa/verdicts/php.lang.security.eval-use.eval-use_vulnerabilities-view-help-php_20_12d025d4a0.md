# php.lang.security.eval-use.eval-use @ vulnerabilities/view_help.php:20

**Verdict:** TP · **Confidence:** High (0.93) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

User‑controlled GET parameters are used to build a file path whose contents are fed directly into eval without any sanitisation, providing a clear RCE vector.

## Data flow

source (line 14 $_GET['id'] / line 16 $_GET['locale']) → variable assignment ($id, $locale) → file path construction inside eval call (line 20) → file_get_contents reads file → eval execution (line 20)

## Answers

1. 1. The dangerous data originates from the HTTP GET parameters: $_GET['id'] (line 14) and $_GET['locale'] (line 16). These are attacker‑controlled inputs.
2. 2. Data flow: line 14 assigns $id = $_GET['id']; line 16 assigns $locale = $_GET['locale']; line 19 checks $locale; line 20 (or line 22) builds a file path using $id (and $locale) → file_get_contents reads that file → the file contents are concatenated with PHP tags and passed to eval(). No other functions intervene.
3. 3. No validation, sanitization, or encoding is performed on $id or $locale before they are used in the file path or passed to eval. The only checks are array_key_exists, which do not validate content.
4. 4. The sink is the eval() call on line 20 (and line 22 in the else branch). It executes PHP code that comes from a file whose name is controlled by user input, making it exploitable.
5. 5. The surrounding framework (dvwaPageStartup, dvwaPageNewGrab, etc.) does not provide any automatic protection for eval; the code uses raw eval with no escaping or sandboxing.
6. 6. The page requires an authenticated user (dvwaPageStartup(array('authenticated')) on line 6), so an attacker must be logged in, but no admin privileges are required.
7. 7. If an attacker can influence the file that is read (e.g., by controlling $id to point to a writable/uploaded file), they can achieve Remote Code Execution (RCE) on the server, and potentially read arbitrary files.
8. 8. The weakest link is the lack of any input validation/whitelisting for $id (and $locale) before they are used to construct a file path that is later evaluated. This unchecked user input directly leads to the eval sink.
