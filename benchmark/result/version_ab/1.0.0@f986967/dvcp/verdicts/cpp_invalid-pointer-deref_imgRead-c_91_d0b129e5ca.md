# cpp/invalid-pointer-deref @ imgRead.c:91

**Verdict:** TP · **Confidence:** High (0.92) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code reads untrusted values from a file, uses them to compute an allocation size, and then indexes one byte past the allocated buffer without any bounds checks, matching the invalid‑pointer‑dereference pattern.

## Data flow

source (line 42: fread into img) → transform (line 82: size3 = img.width / img.height) → transform (line 86: buff4 = malloc(size3)) → sink (line 91: OOBR_heap = buff4[size3])

## Answers

1. 1. The dangerous data originates from the image file read by `fread(&img,sizeof(img),1,fp)` at line 42. The fields `img.width` and `img.height` come from this untrusted file, so the source is external file input (user‑controlled).
2. 2. Data flow: line 42 reads `img` from the file; line 82 computes `int size3 = img.width / img.height;`; line 86 allocates `buff4` with `malloc(size3)`; line 91 reads `buff4[size3]` into `OOBR_heap`.
3. 3. No validation, sanitization, or encoding is performed. There is no check that `img.height` is non‑zero before the division, nor any bounds check that `size3` is less than the allocated size before the array access at line 91. Thus the data is unsanitized and the checks are insufficient.
4. 4. The sink is the out‑of‑bounds read at line 91: `char OOBR_heap = buff4[size3];`. Accessing `buff4` at index `size3` reads one byte past the allocated buffer, which is undefined behaviour.
5. 5. The C runtime library and `malloc` provide no automatic bounds checking. No framework‑level protection exists for this raw pointer access.
6. 6. Any attacker who can supply a file path to the program (via the command‑line argument) can influence the contents of the image file, so the required privilege level is effectively unauthenticated/any local user who can run the binary.
7. 7. The concrete impact is memory‑corruption: an out‑of‑bounds read can leak adjacent memory contents, cause crashes, or be chained with other bugs (e.g., use‑after‑free) to achieve code execution.
8. 8. The weakest link is the complete lack of validation on `img.width`/`img.height` and on the computed `size3` before using it as an index into `buff4`. This allows the OOB read at line 91.
