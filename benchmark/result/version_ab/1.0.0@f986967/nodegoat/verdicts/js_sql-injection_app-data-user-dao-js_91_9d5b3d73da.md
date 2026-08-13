# js/sql-injection @ app/data/user-dao.js:91

**Verdict:** TP · **Confidence:** High (0.94) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The externally supplied `userName` flows unchanged into a MongoDB query filter without any sanitisation, and the driver provides no automatic escaping, enabling a classic NoSQL injection that can bypass authentication.

## Data flow

req.body (external input) → validateLogin parameter `userName` (line 57) → query object field `userName` (line 91) → usersCol.findOne (line 91)

## Answers

1. 1. **Source** – The data originates from the HTTP request body (`req.body`). The scanner identified this as the external source (line 57 in the original data‑flow summary). This is attacker‑controlled network input.
2. 2. **Data‑flow trace** – `req.body` → passed as the `userName` argument to `validateLogin` (function parameter on line 57 of the original snippet, also the first parameter of the arrow function on line 57 of the `validateLogin` definition). Inside `validateLogin` the value is not reassigned or transformed; it is directly referenced in the query object on line 91 (`userName: userName`). No intermediate sanitizers or converters are present.
3. 3. **Validation / sanitization** – No validation, sanitisation, or encoding of `userName` is performed anywhere in `validateLogin`. The only operation on the value is the plain inclusion in the MongoDB filter (line 91). Therefore the input is not protected against NoSQL‑injection payloads.
4. 4. **Sink** – The sink is the MongoDB query on line 91: `usersCol.findOne({ userName: userName }, validateUserDoc);`. Supplying a crafted `userName` (e.g., an object containing `$gt`, `$ne`, etc.) can manipulate the query semantics and bypass authentication.
5. 5. **Framework / library protections** – The native MongoDB Node.js driver does **not** automatically escape or type‑check values placed in a query filter. There is no ORM layer or query‑builder that would parameterise this input, so no automatic protection exists at this sink.
6. 6. **Privilege / authentication state** – `validateLogin` is part of the public login endpoint. Any client, even an unauthenticated attacker, can invoke it by sending a request with a body containing `userName` and `password`.
7. 7. **Security impact** – An attacker who controls `userName` can perform a NoSQL injection to locate an arbitrary user document or bypass password checking, resulting in unauthorized account access and potential data theft or privilege escalation.
8. 8. **Weakest link** – The complete absence of any input validation or sanitisation for `userName` before it reaches the database query (line 91) is the weakest link, making the injection feasible.
