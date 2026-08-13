# javascript.browser.security.eval-detected.eval-detected @ vulnerabilities/javascript/source/high.js:1

**Verdict:** FP · **Confidence:** Low (0.4) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 4

## Reasoning

The flagged line (line 1) only defines an array and does not contain an `eval(` call. The actual `eval` invocation later in the file builds its argument entirely from internal constants and obfuscated transformations; no attacker‑controlled data reaches it. Consequently, there is no exploitable code‑execution path, making the finding a false positive.
