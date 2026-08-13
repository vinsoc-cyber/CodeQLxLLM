# cpp/invalid-pointer-deref @ imgRead.c:91

**Verdict:** TP · **Confidence:** High (0.92) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads attacker‑controlled dimensions from a file, uses them to allocate a buffer of exactly `size3` bytes, and then reads `buff4[size3]` without any bounds check, resulting in a clear out‑of‑bounds read vulnerability.

## Data flow

source (line 42 fread) → compute size3 (line 82) → malloc (line 86) → OOB read (line 91)

## Answers

1. 1. The data originates from the image file read by `fread(&img,sizeof(img),1,fp)` at line 42. The fields `img.width` and `img.height` are populated from the file contents, which are attacker‑controlled.
2. 2. Flow: `img.width`/`img.height` (line 42) → compute `size3 = img.width/img.height` (line 82) → allocate `buff4 = malloc(size3)` (line 86) → read `buff4[size3]` into `OOBR_heap` (line 91).
3. 3. No validation or sanitization is performed on `img.width` or `img.height` before the division (line 82) or before using `size3` as an allocation size (line 86) or as an index (line 91). The checks are absent, so they are insufficient.
4. 4. The sink is the out‑of‑bounds read at line 91: `char OOBR_heap = buff4[size3];` which accesses one element past the allocated buffer (or dereferences a NULL/zero‑size allocation).
5. 5. The C standard library `malloc` and array indexing provide no automatic bounds checking; there is no framework‑level protection here.
6. 6. Any attacker who can supply a crafted image file to the program (e.g., by running the binary with a malicious file) can trigger the path. No authentication is required beyond being able to invoke the program.
7. 7. The OOB read can lead to memory corruption, information disclosure, crashes (DoS) and, in a broader exploit chain, possible remote code execution.
8. 8. The weakest link is the complete lack of validation on `img.width`/`img.height` before they are used to compute `size3` and index the allocated buffer. This missing check enables the out‑of‑bounds access.
