# cpp/path-injection @ imgRead.c:132

**Verdict:** TP · **Confidence:** Low (0.3) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 2

## Reasoning

The user‑controlled command‑line argument is passed directly to `fopen` without any checks, creating a clear path‑injection vulnerability; no mitigations are visible. [calibration: CLI argv path source with no trust boundary — operator-controlled path in a standalone tool, likely False Positive]

## Data flow

argv (line 126) → argv[1] access (line 132) → ProcessImage(filename) (line 132) → fopen(filename,"r") (Statement 1 in ProcessImage)

## Answers

1. 1. The source is the command‑line argument array `argv`; the program uses `argv[1]` supplied by whoever runs the executable (lines 126‑132).
2. 2. Data flow: `argv` (source at line 126) → array element `argv[1]` accessed at line 132 → passed as the `filename` parameter to `ProcessImage` (line 132) → used directly in `fopen(filename, "r")` inside `ProcessImage` (the statement marked “Statement 1”). No other intermediate variables are involved.
3. 3. No validation, sanitisation, or encoding of `filename` is performed before the `fopen` call. The only code that touches `filename` is the direct `fopen` call; there are no checks for absolute paths, directory traversal, or allowed extensions.
4. 4. The sink is the call to `fopen` inside `ProcessImage` (statement 1). Supplying an uncontrolled filename to `fopen` can cause arbitrary file reads (path traversal) or, if the program runs with elevated privileges, exposure of privileged files.
5. 5. The C standard library `fopen` does not provide automatic path sanitisation. No framework‑level protection is present in the shown code.
6. 6. An attacker only needs the ability to invoke the program with a crafted argument. This is the same privilege level as the user running the binary; if the binary were set‑uid/root or otherwise privileged, the impact escalates accordingly.
7. 7. The concrete impact is unauthorized file access – an attacker can read any file readable by the process, leading to information disclosure or potential denial‑of‑service (e.g., by opening large files). No code execution is directly introduced by this sink.
8. 8. The weakest link is the absence of any validation or sanitisation of the command‑line filename before it reaches `fopen`. This lack of defence makes the path‑injection feasible.
