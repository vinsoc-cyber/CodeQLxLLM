# javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** High (0.93) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 4

## Reasoning

The RegExp is built from a constant literal, not from attacker‑controlled input, so the reported non‑literal RegExp does not constitute a ReDoS risk.

## Data flow

static array a (line 1) → b('0x7') → eval argument d → h(f) (internal loop) → new RegExp('\x5cb'+h(f)+'\x5cb','g') (inside eval)

## Answers

1. 1. The only data that eventually reaches the RegExp constructor comes from the static array `a` defined on line 1 (`var a=[...]`). No user‑controlled, file, network or database input is read in the shown code.
2. 2. Data flow: `a` (line 1) → `b('0x7')` (lookup in the array) → first argument `d` of the outer `eval` call → inside the evaluated function, `h(f)` builds a string using the loop index `f` (which is an internal counter) → the built string is concatenated into `new RegExp('\x5cb'+h(f)+'\x5cb','g')` (inside the `while(f--)` loop, near the end of the snippet).
3. 3. No validation, sanitisation or encoding is performed on this data at any step. This is acceptable because the data originates from a constant literal, not from an attacker.
4. 4. Sink: the `RegExp` constructor call `new RegExp('\x5cb'+h(f)+'\x5cb','g')` (inside the `while(f--)` loop of the evaluated function). The danger would be a ReDoS only if the pattern were attacker‑controlled.
5. 5. No framework or library‑level protection is involved in this RegExp construction; it is a plain JavaScript `RegExp` call.
6. 6. The code can be executed by any caller of the surrounding script, but because the pattern is static, an attacker does not need any particular privilege to trigger it – however there is no attacker‑controlled input to exploit.
7. 7. Since the regular‑expression pattern is static, an attacker cannot influence its complexity; therefore the concrete impact is *none* (no ReDoS, no RCE, no data leakage).
8. 8. There is no weak link: the only data source is a constant literal, so the lack of validation does not constitute a vulnerability.
