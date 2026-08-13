# js/polynomial-redos @ app/routes/profile.js:61

**Verdict:** TP · **Confidence:** High (0.93) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The code applies a nested‑quantifier regex to attacker‑controlled input without any mitigation, which is a classic polynomial ReDoS vulnerability.

## Data flow

source (line 50) → variable bankRouting (line 49) → regexPattern (line 59) → sink test (line 61)

## Answers

1. 1. The ultimate source is `req.body` on line 50, which contains data supplied by the HTTP client and is therefore attacker‑controlled.
2. 2. Data flow: `req.body` (line 50) → destructuring assignment creates variable `bankRouting` on line 49 → `regexPattern` is defined on line 59 → `regexPattern.test(bankRouting)` is executed on line 61.
3. 3. No validation, sanitization, or encoding is performed before the regex test; the only check is the regex itself, which contains nested quantifiers and is insufficient to prevent ReDoS.
4. 4. The sink is the call to `regexPattern.test(bankRouting)` on line 61. Executing this regular expression can cause exponential‑time backtracking, leading to a denial‑of‑service condition.
5. 5. Neither Express nor the standard JavaScript runtime provides automatic mitigation for user‑controlled regular expressions; there is no framework‑level protection here.
6. 6. The handler runs after extracting `userId` from `req.session` (lines 78‑80), so an attacker must be an authenticated user (any logged‑in user) to reach this code path.
7. 7. If a crafted `bankRouting` value is supplied, the server can be forced into high CPU consumption, resulting in a denial‑of‑service (DoS) impact.
8. 8. The weakest link is the vulnerable regular expression `/([0-9]+)+\#/` defined on line 59 (used on line 61). The nested `+` quantifiers enable catastrophic backtracking with no preceding sanitization.
