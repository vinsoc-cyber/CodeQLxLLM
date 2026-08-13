# js/polynomial-redos @ app/routes/session.js:181

**Verdict:** FP · **Confidence:** High (0.94) · **Truth:** real · **Grade:** MISS · **Iterations:** 3

## Reasoning

The flagged sink is a simple linear regular expression that cannot cause polynomial‑time back‑tracking, so the reported ReDoS risk is unfounded.

## Data flow

source (line 198) → email variable (line 191‑192) → validateSignup argument (line 206) → email param (line 138) → sink (line 181)

## Answers

1. 1. The potentially dangerous data originates from the HTTP request body (`req.body`) at line 198 in `handleSignup`. This is attacker‑controlled input.
2. 2. Data‑flow trace: line 198 (`req.body`) → line 191‑192 (destructuring creates variable `email`) → line 206 (passed as argument to `validateSignup`) → line 138 (parameter `email` of `validateSignup`) → line 181 (`EMAIL_RE.test(email)`).
3. 3. No sanitization or encoding is performed before the regex test. The only validation is the regular‑expression test itself at line 181. The pattern `/^[\S]+@[\S]+\.[\S]+$/` contains only simple, linear quantifiers (`+`) and no nested quantifiers, alternations, or back‑references, so it does not introduce catastrophic back‑tracking.
4. 4. The sink is the call to `EMAIL_RE.test(email)` on line 181, where the user‑supplied email string is matched against a regular expression.
5. 5. No framework or library automatically protects this operation; it is a direct call to the native JavaScript RegExp engine.
6. 6. The code resides in the signup handler, which is reachable by any unauthenticated client that can POST to the signup endpoint.
7. 7. If the regex were vulnerable, an attacker could cause a denial‑of‑service (DoS) by supplying a crafted email string that triggers exponential back‑tracking. Because the regex is linear, there is no realistic impact.
8. 8. The only potential weak link would be the regex itself, but its structure is safe (no nested quantifiers, no alternation, no back‑references). Therefore the defense chain is complete for this path.
