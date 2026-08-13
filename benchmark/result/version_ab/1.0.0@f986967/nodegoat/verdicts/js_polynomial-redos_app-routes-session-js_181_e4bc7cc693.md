# js/polynomial-redos @ app/routes/session.js:181

**Verdict:** FP · **Confidence:** High (0.93) · **Truth:** real · **Grade:** MISS · **Iterations:** 3

## Reasoning

The regex used for email validation is linear and lacks nested quantifiers, so it cannot cause polynomial‑time backtracking. No other unsafe operation follows, making the finding a false positive.

## Data flow

source (line 198) → email variable (line 192) → validateSignup argument (line 206) → email parameter (line 138) → sink EMAIL_RE.test(email) (line 181)

## Answers

1. Q1: The ultimate source is `req.body` (line 198), i.e., attacker‑controlled data from the HTTP request body.
2. Q2: Data flow – `req.body` is destructured at lines 191‑198 assigning `email` (line 192). The `email` variable is passed to `validateSignup` at line 206, becomes the parameter `email` of `validateSignup` (declared at line 138), and is then used in `EMAIL_RE.test(email)` at line 181.
3. Q3: The only validation applied to `email` before the sink is the regular‑expression test itself (`EMAIL_RE.test(email)`). No additional sanitization, encoding, or length‑checking is performed.
4. Q4: The sink is the regex test `EMAIL_RE.test(email)` on line 181. The operation could be dangerous only if the pattern allowed catastrophic backtracking.
5. Q5: Express (the web framework) does not automatically protect against user‑supplied regex evaluation, and no wrapper library is used here.
6. Q6: The `handleSignup` route is reachable by any unauthenticated client (the route is mounted at `/signup` via `app.post` in index.js), so an attacker can trigger the code without prior authentication.
7. Q7: If the regex were vulnerable, the impact would be a Denial‑of‑Service (CPU exhaustion) via ReDoS. No code execution or data leakage occurs.
8. Q8: The weakest link is the absence of explicit length limits on `email`. However, the regex `/^[\S]+@[\S]+\.[\S]+$/` contains only simple, non‑nested quantifiers and is linear‑time; it does not exhibit polynomial‑time backtracking. Therefore, there is no exploitable weakness.
