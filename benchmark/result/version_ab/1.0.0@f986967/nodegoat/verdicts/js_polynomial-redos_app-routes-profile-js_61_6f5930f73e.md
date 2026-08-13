# js/polynomial-redos @ app/routes/profile.js:61

**Verdict:** TP · **Confidence:** High (0.94) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

Attacker‑controlled input reaches a RegExp with nested quantifiers and no safeguards, creating an exploitable ReDoS path accessible to authenticated users.

## Data flow

source (line 50) → sink (line 61)

## Answers

1. 1. The potentially dangerous data originates from the HTTP request body (req.body) on line 50. This is attacker‑controlled input provided by a client making a POST /profile request.
2. 2. Data flow trace:
   - Line 50: `const { ... bankRouting } = req.body;` extracts the `bankRouting` field from the request body.
   - Line 59: The regular expression literal `const regexPattern = /([0-9]+)+\#/;` is defined locally (no external definition, see global:regexPattern is absent).
   - Line 61: `regexPattern.test(bankRouting)` evaluates the attacker‑controlled value.
   Thus the flow is `req.body.bankRouting` → local variable `bankRouting` (line 50) → RegExp test (line 61).
3. 3. No validation, sanitization, or encoding is performed on `bankRouting` before the RegExp test. The only check is the RegExp itself, which contains nested quantifiers (`+)+`) that are known to cause catastrophic backtracking. Therefore the validation is insufficient for ReDoS protection.
4. 4. The sink is the call to `regexPattern.test(bankRouting)` on line 61. Executing this vulnerable regular expression on attacker‑controlled input can cause exponential time processing (catastrophic backtracking), leading to a denial‑of‑service.
5. 5. The framework (Express) does not provide any automatic protection for RegExp execution. The `isLoggedIn` middleware (see caller context) only ensures the user is authenticated; it does not limit the size or content of `bankRouting` nor enforce safe‑regex checks.
6. 6. Because the route is mounted as `app.post("/profile", isLoggedIn, profileHandler.handleProfileUpdate);` (caller context), an attacker must be an authenticated user with a valid session to reach this code path. Unauthenticated users cannot trigger it, but any logged‑in user can supply arbitrary `bankRouting` values.
7. 7. The concrete security impact is a denial‑of‑service (DoS) via ReDoS. An attacker can craft a large string of zeros (or any digit) followed by a `#` that forces the RegExp to backtrack exponentially, consuming CPU resources and potentially rendering the server unresponsive.
8. 8. The weakest link is the insecure regular expression itself (line 59/61). There is no preceding length check, whitelist validation, or use of a safe‑regex library to mitigate backtracking. This makes the ReDoS vulnerability exploitable by any authenticated attacker.
