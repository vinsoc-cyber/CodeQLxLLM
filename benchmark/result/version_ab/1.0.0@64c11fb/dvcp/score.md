# Score — 1.0.0@64c11fb

Model `ollama/gpt-oss:120b` · temp `0` · panel `sha256:eebf118bd…` · 2026-08-13T16:20:05

precision **80%** · recall **100%** · TP 5 (real 4, false-alarm 1) · real 4 · not-real 1 · NMD 0 · err 0 · $0.0
_resources:_ 21k in / 6k out · cache 0% · 73.5s model-time · iters μ1.0

| finding | truth | verdict | grade | conf |
|---|---|---|---|---|
| cpp/double-free@imgRead.c:62 | real | TP | CORRECT | High |
| cpp/invalid-pointer-deref@imgRead.c:91 | real | TP | CORRECT | High |
| cpp/invalid-pointer-deref@imgRead.c:95 | real | TP | CORRECT | High |
| cpp/path-injection@imgRead.c:132 | not-real | TP | FALSE-ALARM | Low |
| cpp/use-after-free@imgRead.c:67 | real | TP | CORRECT | High |
