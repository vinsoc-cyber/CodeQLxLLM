# cpp/double-free @ imgRead.c:62

**Verdict:** TP · **Confidence:** High (0.92) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code allocates `buff1`, frees it, and then may free it again based on `size1 % 2`. The size is attacker‑controlled via the image file, so the double‑free can be reliably triggered, making the finding a real exploitable vulnerability.

## Data flow

argv[1] → fread(&img) (line 42) → size1 = img.width + img.height (line 54) → malloc → free (line 59) → second free (line 62)

## Answers

1. 1. The data originates from an external file read into `struct Image img` by `fread` (line 42). The file name itself comes from the command‑line argument `argv[1]` (see `main`), but the double‑free condition depends on the contents of the file (width/height fields).
2. 2. Data flow: `argv[1]` → `ProcessImage(filename)` (line 29) → `fread(&img, sizeof(img), 1, fp)` fills `img` (line 42) → `size1 = img.width + img.height` (line 54) → `buff1 = malloc(size1)` (line 55) → `memcpy(buff1, img.data, sizeof(img.data))` (line 58) → `free(buff1)` (line 59) → conditional `if (size1 % 2 == 0) free(buff1);` (line 62).
3. 3. No validation, sanitisation or bounds checking is performed on `size1` or on the pointer after the first `free`. The code does not check the result of `malloc` nor prevent a second `free`, so there is no defense for this vulnerability.
4. 4. The sink is the second call to `free(buff1)` at line 62. Because `buff1` was already freed on line 59, this second `free` constitutes a double‑free, which can corrupt the heap.
5. 5. The C standard library `free` does not provide automatic protection against double‑free. No additional framework or library safeguards are present.
6. 6. An attacker only needs the ability to run the program and supply a crafted image file (and optionally the filename via the command line). This is a local, unauthenticated attacker scenario; the privilege level is the same as the user executing the program.
7. 7. Double‑free can lead to heap corruption, enabling arbitrary code execution, privilege escalation, or at minimum a denial‑of‑service by crashing the program.
8. 8. The weakest link is the missing guard that prevents the second `free` (no check that `buff1` is still allocated). This allows the double‑free to be triggered whenever `size1` is even.
