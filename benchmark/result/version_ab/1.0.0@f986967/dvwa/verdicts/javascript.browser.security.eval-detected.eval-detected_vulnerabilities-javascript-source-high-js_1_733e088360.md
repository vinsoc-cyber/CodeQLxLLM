# javascript.browser.security.eval-detected.eval-detected @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** High (0.9) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 3

## Reasoning

The `eval` call only executes code built from hard‑coded constants; there is no attacker‑controllable input reaching the sink, so the finding is a false positive.

## Data flow

static literals (array a, line 1) → helper b (line 2) → eval arguments (last line) → eval execution

## Answers

1. 1. The only data used as the argument to `eval` comes from static literals defined in this file (the array `a` on line 1 and the helper `b` on line 2). No external request, file read, or user‑controlled variable is visible.
2. 2. Data flow: static array `a` → helper `b` (line 2) → arguments to the anonymous function passed to `eval` (last line). The values are all constant indices into `a` (e.g., `b('0x7')`, `b('0x8')[b('0x9')]('|')`).
3. 3. No validation, sanitization, or encoding is performed because the inputs are not user‑controlled; they are compile‑time constants.
4. 4. The sink is the `eval` call at the very end of the snippet (`eval(function(d,e,f,g,h,i){…})(b('0x7'),0x3e,0x137,b('0x8')[b('0x9')]('|'),0x0,{});`).
5. 5. No framework‑level protection applies; this is raw JavaScript executed in the browser (or a script environment).
6. 6. Because the evaluated code is assembled only from static data, no attacker privilege level can influence this path.
7. 7. If an attacker could inject data, the impact would be Remote Code Execution, but such injection is impossible with the visible code.
8. 8. There is no weak link: the data reaching `eval` is entirely static, so the lack of sanitization does not matter.
