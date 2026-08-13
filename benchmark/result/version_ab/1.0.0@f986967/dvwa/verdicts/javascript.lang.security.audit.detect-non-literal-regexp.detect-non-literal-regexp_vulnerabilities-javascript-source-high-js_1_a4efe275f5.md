# javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** High (0.95) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 5

## Reasoning

The rule flags a RegExp() call with a function argument, but the flagged line (1) is an array literal and no RegExp constructor appears in the provided code or any supplied context. Hence the reported issue is a false positive.

## Answers

1. 1. The code snippet does not contain a RegExp constructor call, so no user‑controlled source for a RegExp pattern is visible. Not visible in provided context.
2. 2. No data flow involving a RegExp pattern can be traced because the RegExp invocation is absent. Not visible in provided context.
3. 3. No validation, sanitisation, or encoding of a RegExp pattern is present, because no such pattern is created. Not visible in provided context.
4. 4. There is no RegExp usage (sink) in the shown code. The only visible statements are array literals and obfuscated logic. Not visible in provided context.
5. 5. No library or framework handling of RegExp objects is exercised in the snippet. Not applicable / not visible.
6. 6. Since no RegExp call exists, no privilege level is required to reach it. Not applicable.
7. 7. Without a RegExp pattern being constructed from attacker‑controlled data, there is no ReDoS impact to evaluate. Not applicable.
8. 8. The weakest link is the absence of the vulnerable construct itself – the code simply does not create a RegExp from a function argument, so there is no exploitable path.
