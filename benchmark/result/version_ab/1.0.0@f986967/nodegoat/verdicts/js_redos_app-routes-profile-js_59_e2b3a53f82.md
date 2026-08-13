# js/redos @ app/routes/profile.js:59

**Verdict:** TP · **Confidence:** Medium (0.73) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The attacker‑controlled `bankRouting` value flows directly into a regex with nested greedy quantifiers. This pattern is known to cause exponential back‑tracking, and there is no visible input length limit or sanitization, so an attacker can trigger a CPU‑intensive ReDoS, resulting in DoS.

## Data flow

source (req.body.bankRouting line 49) → regexPattern.test(bankRouting) line 61 (sink)

## Answers

1. 1. Source: `bankRouting` originates from the HTTP request body via `req.body.bankRouting` (line 49), i.e., an external network source controlled by the client.
2. 2. Data flow: `bankRouting` (line 49) → passed directly to `regexPattern.test(bankRouting)` (line 61). No intermediate assignments or transformations.
3. 3. No validation, sanitization, or encoding occurs before the regex test. The only “validation” is the regex itself (line 59‑61), which is the vulnerable construct.
4. 4. Sink: the call to `regexPattern.test(bankRouting)` on line 61. The regular expression `/([0-9]+)+\#/` contains nested greedy quantifiers that can cause exponential back‑tracking, making the regex execution a denial‑of‑service (DoS) sink.
5. 5. No framework‑level protection mitigates this regex execution; Express/Node.js will execute the pattern as‑is.
6. 6. The handler runs after a session is read (`req.session.userId` on line 78), so an attacker must be an authenticated user (or any client that can obtain a valid session cookie).
7. 7. Impact: catastrophic back‑tracking can consume CPU resources and stall the event loop, leading to a denial‑of‑service for the server. No code execution or data exposure occurs.
8. 8. Weakest link: the insecure regular expression `/([0-9]+)+\#/` on line 59, used without length checks or safer alternatives, provides the exploitable ReDoS vector.
