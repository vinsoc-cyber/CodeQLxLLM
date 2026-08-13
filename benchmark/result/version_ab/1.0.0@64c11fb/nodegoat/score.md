# Score — 1.0.0@64c11fb

Model `ollama/gpt-oss:120b` · temp `0` · panel `sha256:1179d5607…` · 2026-08-13T16:28:13

precision **93%** · recall **88%** · TP 15 (real 14, false-alarm 1) · real 16 · not-real 1 · NMD 0 · err 0 · $0.0
_resources:_ 259k in / 36k out · cache 0% · 787.5s model-time · iters μ2.71

| finding | truth | verdict | grade | conf |
|---|---|---|---|---|
| js/clear-text-cookie@server.js:78 | real | TP | CORRECT | High |
| js/code-injection@app/data/allocations-dao.js:78 | real | TP | CORRECT | High |
| js/code-injection@app/routes/contributions.js:32 | real | TP | CORRECT | High |
| js/code-injection@app/routes/contributions.js:33 | real | TP | CORRECT | High |
| js/code-injection@app/routes/contributions.js:34 | real | TP | CORRECT | High |
| js/indirect-command-line-injection@Gruntfile.js:166 | not-real | TP | FALSE-ALARM | High |
| js/log-injection@app/routes/session.js:64 | real | TP | CORRECT | High |
| js/missing-rate-limiting@app/routes/index.js:34 | real | TP | CORRECT | High |
| js/missing-token-validation@server.js:78 | real | TP | CORRECT | High |
| js/polynomial-redos@app/routes/profile.js:61 | real | TP | CORRECT | High |
| js/polynomial-redos@app/routes/session.js:181 | real | FP | MISS | High |
| js/redos@app/routes/profile.js:59 | real | TP | CORRECT | High |
| js/request-forgery@app/routes/research.js:16 | real | TP | CORRECT | High |
| js/server-side-unvalidated-url-redirection@app/routes/index.js:72 | real | TP | CORRECT | High |
| js/session-fixation@app/routes/index.js:34 | real | FP | MISS | Low |
| js/sql-injection@app/data/user-dao.js:104 | real | TP | CORRECT | High |
| js/sql-injection@app/data/user-dao.js:91 | real | TP | CORRECT | High |
