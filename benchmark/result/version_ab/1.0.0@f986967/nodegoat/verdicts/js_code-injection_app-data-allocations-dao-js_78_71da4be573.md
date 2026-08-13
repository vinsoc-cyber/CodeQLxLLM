# js/code-injection @ app/data/allocations-dao.js:78

**Verdict:** TP · **Confidence:** High (0.92) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 4

## Reasoning

An attacker‑controlled `threshold` value is injected unsanitised into a MongoDB `$where` JavaScript expression, which the database evaluates, providing a clear NoSQL code‑injection vulnerability.

## Data flow

threshold (line 57) → searchCriteria() (line 62) → $where template string (line 78) → allocationsCol.find(...).toArray (line 86)

## Answers

1. 1. The dangerous data originates from the function parameter `threshold` of `getByUserIdAndThreshold` (line 57). The static analysis marks this as a source, implying it can be supplied by an external request.
2. 2. Data‑flow trace: 
   - `threshold` (parameter) at line 57
   - Passed unchanged into the arrow function `searchCriteria` (lines 60‑62)
   - Interpolated directly into a template string that becomes the `$where` clause (line 78)
   - The object returned by `searchCriteria()` is supplied to `allocationsCol.find(...).toArray` (line 86).
3. 3. No validation, sanitisation, or encoding of `threshold` is performed. The only sanitisation code is present but commented‑out (lines 64‑76). Hence the value reaches the sink untouched.
4. 4. The sink is the `$where` string constructed at line 78, which is executed by MongoDB when the driver runs the query at line 86. `$where` evaluates JavaScript on the database server, so arbitrary code can be injected.
5. 5. The MongoDB Node.js driver does not automatically escape `$where` strings, and no application‑level protection is visible.
6. 6. The method is intended to be called with a `userId` and `threshold`, typically from a request handler. Therefore an authenticated user who can influence the `threshold` argument can trigger the vulnerable path.
7. 7. An attacker controlling `threshold` can perform a NoSQL injection that executes arbitrary JavaScript on the MongoDB server, leading to data theft, modification, privilege escalation within the database, or denial‑of‑service.
8. 8. The weakest link is the absence of any sanitisation/validation of `threshold` before it is interpolated into the `$where` clause (line 78).
