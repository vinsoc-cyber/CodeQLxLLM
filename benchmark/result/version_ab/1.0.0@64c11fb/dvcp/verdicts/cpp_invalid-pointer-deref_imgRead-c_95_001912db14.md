# cpp/invalid-pointer-deref @ imgRead.c:95

**Verdict:** TP · **Confidence:** High (0.92) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code allocates a buffer of length `size3` (derived from untrusted file data) and then writes to `buff4[size3]`, which is one byte beyond the allocated region. No bounds checks or sanitization are present, making the out‑of‑bounds write exploitable.

## Data flow

source: fread into img (line 42) → size3 = img.width / img.height (line 82) → malloc(size3) → buff4 (line 86) → OOB write buff4[size3] = 'c' (line 95)

## Answers

1. 1. The dangerous data originates from the image file that is read into `struct Image img` by `fread` at line 42. The fields `img.width` and `img.height` are therefore controlled by the file contents (an external, attacker‑controlled source).
2. 2. Data flow: `img.width` and `img.height` (populated by `fread` line 42) → `size3 = img.width / img.height` at line 82 → `malloc(size3)` creates `buff4` at line 86 → the index `size3` is used in the write `buff4[size3] = 'c'` at line 95.
3. 3. No validation, sanitization, or encoding is performed on `img.width`, `img.height`, or the derived `size3`. The division (line 82) can also cause divide‑by‑zero, and there is no bounds check before the write at line 95.
4. 4. The sink is the heap write `buff4[size3] = 'c'` on line 95. Because `buff4` was allocated with exactly `size3` bytes (line 86), the write accesses one byte past the allocated region, causing an out‑of‑bounds write.
5. 5. The C standard library provides no automatic bounds checking for raw pointer arithmetic or `malloc`. No additional framework or library protection is present.
6. 6. Any user who can invoke the program and supply a file name (via the command‑line argument `argv[1]` in `main` lines 4‑9) can trigger this path. Thus the required privilege level is effectively unauthenticated/local user.
7. 7. An out‑of‑bounds heap write can corrupt heap metadata, leading to arbitrary code execution, memory corruption, or a crash (Denial‑of‑Service). The primary impact is potential RCE.
8. 8. The weakest link is the complete lack of validation on `size3` before it is used both as the allocation size (line 86) and as an index (line 95). This unchecked value enables the out‑of‑bounds write.
