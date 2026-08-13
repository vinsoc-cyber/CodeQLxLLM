# php.lang.security.phpinfo-use.phpinfo-use @ phpinfo.php:8

**Verdict:** TP · **Confidence:** Low (0.6) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

Although no attacker‑controlled data is passed, the unconditional phpinfo() call reveals sensitive configuration to any authenticated user, constituting an exploitable information‑disclosure vulnerability.

## Data flow

direct call to phpinfo() on line 8 (no source, no transformation)

## Answers

1. 1. No external user‑controlled data flows into phpinfo(); the function itself does not take arguments, so there is no source of dangerous data in this snippet.
2. 2. The data flow is trivial: the script directly calls phpinfo() on line 8 with no intermediate variables or transformations.
3. 3. No validation, sanitization, or encoding is applicable because no data is being passed to the sink.
4. 4. The sink is the phpinfo() call on line 8, which outputs detailed server and PHP configuration information.
5. 5. The only framework interaction is dvwaPageStartup() on line 6, which enforces that the user is authenticated, but it does not mask or restrict phpinfo() output.
6. 6. An attacker must be an authenticated user (any logged‑in user) to reach this code, as enforced by dvwaPageStartup() on line 6.
7. 7. The concrete impact is information disclosure (CWE‑200): an authenticated attacker can view PHP version, loaded extensions, environment variables, and other sensitive configuration details.
8. 8. The weakest link is the unconditional call to phpinfo() after only a basic authentication check; there is no additional restriction, output filtering, or masking.
