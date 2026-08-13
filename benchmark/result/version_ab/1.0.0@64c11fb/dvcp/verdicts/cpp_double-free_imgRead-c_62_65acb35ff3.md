# cpp/double-free @ imgRead.c:62

**Verdict:** TP · **Confidence:** High (0.92) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code frees the same heap pointer twice without any guard, creating a classic double‑free vulnerability that is exploitable.

## Data flow

malloc(size1) → buff1 (line 55) → free(buff1) (line 59) → free(buff1) again (line 62)

## Answers

1. The data originates from a file supplied by the user (the filename comes from the command‑line argument argv[1] in main, line 1 of the caller, and the file contents are read into struct Image at line 42).
2. size1 is computed from the file fields at line 54, malloc uses it at line 55 to create buff1, memcpy copies data at line 58, buff1 is freed at line 59, and the same pointer is freed again at line 62 inside the conditional.
3. No validation, sanitization, or bounds checks are performed on size1 (lines 54‑55) nor before the second free (line 62); thus there is no protection against the double‑free.
4. The sink is the call to free(buff1) at line 62; freeing the same pointer a second time after it has already been freed at line 59 constitutes the unsafe operation.
5. The C standard library’s free() does not provide automatic double‑free protection; there is no framework‑level guard in this code.
6. Any local user who can invoke the program can supply a filename, so the attacker needs no authentication – an unauthenticated local attacker can trigger the path.
7. A double free can corrupt the heap, leading to crashes (DoS) or, depending on the allocator, arbitrary code execution (RCE).
8. The weakest link is the unconditional second free at line 62 with no check that the pointer has already been freed or set to NULL.
