# js/server-side-unvalidated-url-redirection @ app/routes/index.js:72

**Verdict:** TP · **Confidence:** High (0.94) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The code forwards a user‑controlled query parameter directly to Express's redirect function without any validation, creating an exploitable open‑redirect. The only guard is authentication, which does not mitigate the vulnerability.

## Data flow

source (req.query.url at line 72) → sink (res.redirect at line 72)

## Answers

1. 1. The source is still the user‑controlled query string parameter `url` accessed via `req.query.url` on line 72. No new source information was found.
2. 2. Data flow: `req.query.url` (source at line 72) is passed directly to `res.redirect` on the same line (line 72). No intermediate variables or transformations exist.
3. 3. No validation, sanitization, or encoding is performed on the `url` value before it reaches the sink. The additional context did not provide any definition for `isLoggedIn` or `res.redirect`, so we have no evidence of any checks.
4. 4. The sink is the call to `res.redirect(req.query.url)` on line 72. This causes the server to issue an HTTP redirect to an attacker‑controlled URL, which is the classic open‑redirect vulnerability (CWE‑601).
5. 5. Express’s `res.redirect` does not automatically validate or whitelist the target URL; it simply sets the `Location` header. Therefore the framework provides no protection for this use case.
6. 6. The route is guarded by the `isLoggedIn` middleware (line 70). An attacker must be an authenticated user (any logged‑in user) to trigger the redirect. No admin rights are required.
7. 7. The impact is an open‑redirect: attackers can craft links that appear to point to the legitimate site but redirect victims to malicious sites, enabling phishing or credential‑theft attacks. No server‑side code execution occurs.
8. 8. The weakest link is the complete lack of any validation or allow‑list check on the `url` parameter before calling `res.redirect`. Adding such validation would mitigate the issue.
