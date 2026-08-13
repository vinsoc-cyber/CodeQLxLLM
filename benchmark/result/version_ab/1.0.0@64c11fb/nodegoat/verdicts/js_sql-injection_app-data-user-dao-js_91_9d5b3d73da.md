# js/sql-injection @ app/data/user-dao.js:91

**Verdict:** TP · **Confidence:** High (0.94) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

Attacker‑controlled `userName` flows directly into a MongoDB query without any validation, enabling NoSQL injection that can bypass authentication.

## Data flow

source (req.body, line 57) → parameter userName (line 57) → query object (line 91) → sink usersCol.findOne (line 91)

## Answers

1. 1. The potentially dangerous data originates from an external HTTP request body (`req.body`). The scanner’s data‑flow annotation marks line 57 as the source, which is attacker‑controlled input.
2. 2. Data flow trace:
   - `req.body` (source) → passed as the `userName` argument when `validateLogin` is invoked (not shown but established by the scanner). 
   - Inside `validateLogin`, the parameter `userName` is used directly in the query object on line 91 (`usersCol.findOne({ userName: userName }, validateUserDoc);`). No intermediate transformation occurs.
3. 3. No validation, sanitization, or encoding is applied to `userName` before it reaches the query. The only operations on it are the direct parameter passing (line 57) and inclusion in the query object (line 91), which is insufficient to prevent NoSQL injection.
4. 4. The sink is the MongoDB `findOne` call on line 91. Using attacker‑controlled `userName` as a query value can allow injection of MongoDB operators (e.g., `$gt`, `$ne`) to bypass authentication or retrieve arbitrary documents.
5. 5. The MongoDB driver does not automatically escape or parameterize query values; it trusts the developer. No ORM or additional library is used here, so there is no automatic protection at this point.
6. 6. `validateLogin` is part of the login flow and can be triggered by any client that can send a request to the login endpoint. Therefore an unauthenticated attacker can reach this code path.
7. 7. Exploiting this allows an attacker to craft a `userName` value that manipulates the query, potentially bypassing password verification and logging in as any user. This results in authentication bypass, unauthorized data access, and possible privilege escalation.
8. 8. The weakest link is the complete lack of input validation/sanitization on `userName` before it is used in the database query (steps 2‑3). Adding proper validation, whitelisting, or using a safe query builder would mitigate the vulnerability.
