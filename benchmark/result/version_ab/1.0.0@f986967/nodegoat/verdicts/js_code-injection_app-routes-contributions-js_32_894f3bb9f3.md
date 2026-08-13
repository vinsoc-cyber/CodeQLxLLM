# js/code-injection @ app/routes/contributions.js:32

**Verdict:** TP · **Confidence:** High (0.94) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The code directly evaluates attacker‑controlled input via eval() with no prior sanitization, providing a clear server‑side JavaScript injection path.

## Data flow

source (line 32: req.body.preTax) → sink (line 32: eval(req.body.preTax))

## Answers

1. 1. The dangerous data originates from `req.body` – the HTTP request body supplied by the client (remote/external input) on line 32 (`req.body.preTax`).
2. 2. Data flow: `req.body.preTax` (source, line 32) → passed directly into `eval()` (sink, line 32) → result stored in variable `preTax` (line 32). The same pattern repeats for `afterTax` (line 33) and `roth` (line 34). No other intermediate assignments or transformations occur before the eval call.
3. 3. No validation, sanitization, or encoding is applied before the `eval` calls. The only checks (`isNaN`, range checks) are performed **after** eval on lines 46‑48 and therefore cannot prevent code execution. Hence there is no sufficient mitigation prior to the sink.
4. 4. The sink is the use of `eval()` on line 32 (and similarly lines 33‑34). Executing `eval` with attacker‑controlled strings enables arbitrary JavaScript code execution on the server.
5. 5. Neither Express nor any other library provides automatic protection for the use of `eval`. The code includes a JSLint comment `/*jslint evil: true */` which explicitly allows `eval`. No sandboxing or escaping is applied.
6. 6. The handler extracts `userId` from `req.session` (lines 13‑15, 42‑44), indicating the route is intended for authenticated users. An attacker therefore needs a valid session (i.e., be logged in) but does not need admin privileges to reach this code.
7. 7. If an attacker controls `req.body.preTax` (or the other fields), they can execute arbitrary server‑side JavaScript, leading to remote code execution, data theft/modification, or denial‑of‑service.
8. 8. The single weakest link is the direct call to `eval(req.body.preTax)` on line 32 without any prior sanitization or restriction. This is the point where an attack succeeds.
