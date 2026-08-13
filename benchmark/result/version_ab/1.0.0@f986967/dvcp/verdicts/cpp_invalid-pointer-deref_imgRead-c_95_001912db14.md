# cpp/invalid-pointer-deref @ imgRead.c:95

**Verdict:** TP · **Confidence:** High (0.93) · **Truth:** real · **Grade:** CORRECT · **Iterations:** 1

## Reasoning

The code allocates a heap buffer of length `size3` then writes to index `size3` without any bounds check. `size3` is derived from attacker‑controlled file data, making the out‑of‑bounds write reachable and exploitable.

## Data flow

source (line 42 – fread into img) → transform (line 82 – compute size3) → transform (line 86 – malloc(size3) → buff4) → sink (line 95 – buff4[size3] = 'c')

## Answers

1. 1. The dangerous data originates from the image file read by `fread` on line 42, which fills `img.width` and `img.height`. The file name comes from `argv[1]` (the command‑line argument) making the contents attacker‑controllable via a crafted file. [source: line 42, line 33, line 30‑31] 
2. 2. Data flow: `fread(&img, sizeof(img), 1, fp)` reads raw bytes into `img` (line 42). The fields `img.width` and `img.height` are then used on line 82 to compute `size3 = img.width / img.height`. Line 86 allocates `buff4 = malloc(size3)`. Finally line 95 writes `buff4[size3] = 'c'`. 
3. 3. No validation, sanitization, or encoding is performed on `img.width`, `img.height`, or the derived `size3` before the allocation or the write. The division by zero check and bounds check are absent, so the defenses are insufficient. 
4. 4. The sink is the write on line 95: `buff4[size3] = 'c';` which writes one byte past the heap block returned by `malloc(size3)`, constituting a heap buffer overflow. 
5. 5. The standard C library (`malloc`, raw pointer arithmetic) does not provide automatic bounds checking; therefore there is no library‑level protection for this write. 
6. 6. An attacker only needs to supply a malicious image file (controlled via the command‑line argument and the file system). No authentication is required; the vulnerability can be triggered by any user who can run the program with a chosen file. 
7. 7. The concrete impact is a heap‑based out‑of‑bounds write, which can corrupt adjacent heap metadata and potentially lead to arbitrary code execution or a denial‑of‑service crash. 
8. 8. The weakest link is the lack of any validation of `size3` (and the missing division‑by‑zero check). Without a bounds check before the write, the heap overflow is exploitable.
