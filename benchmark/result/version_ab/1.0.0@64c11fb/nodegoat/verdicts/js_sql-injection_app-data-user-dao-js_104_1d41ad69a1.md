# js/sql-injection @ app/data/user-dao.js:104

**Verdict:** TP · **Confidence:** High (0.94) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

With no callers and no sanitisation, attacker‑controlled `req.body.userName` flows directly into a MongoDB query, allowing NoSQL injection; the driver provides no automatic mitigation.

## Data flow

req.body (line 198) → userName argument (line 103) → query object (line 105) → usersCol.findOne (line 104)

## Answers

1. 1. The ultimate source is `req.body` (line 198), which is attacker‑controlled HTTP request data.
2. 2. Data flow: `req.body` (line 198) → the `userName` property is extracted (the extraction point is not shown in the current repository, but the value is passed directly to `getUserByUserName` as the `userName` argument at line 103) → used unchanged in the query object at line 105 → supplied to `usersCol.findOne` at line 104 (sink).
3. 3. No validation, sanitisation, or encoding of `userName` is visible anywhere in the provided code or in any caller (the analysis reports no callers for `getUserByUserName`). Therefore the value reaches the sink unsanitised.
4. 4. The sink is the MongoDB `findOne` call on line 104, where the query `{ userName: userName }` is built from untrusted input, enabling NoSQL injection.
5. 5. The MongoDB Node driver does not automatically escape or parameterise query values; it treats the supplied object literally, so there is no built‑in protection at this point.
6. 6. Because no callers are recorded, the function is likely reachable from a public API endpoint (e.g., a login or user‑lookup route) that does not require prior authentication, meaning an attacker can invoke it unauthenticated.
7. 7. An attacker could inject query operators (e.g., `{ "$gt": "" }`) or a `$where` JavaScript expression to bypass authentication, retrieve arbitrary user documents, or cause denial‑of‑service, constituting data theft and possible privilege escalation.
8. 8. The weakest link is the complete lack of any input validation or sanitisation before the value is placed into the MongoDB query (step 3).
