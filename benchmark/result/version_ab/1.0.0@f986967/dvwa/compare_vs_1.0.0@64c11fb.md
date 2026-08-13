# Compare — 1.0.0@64c11fb → 1.0.0@f986967

Δprecision **+4%** · Δrecall **-2%** · 2026-08-13T17:13:44

## Flips: 8 (improve 3 · regress 4 · neutral 1)

| finding | truth | prev → cur | dir | conf |
|---|---|---|---|---|
| php.lang.security.audit.openssl-decrypt-validate.openssl-decrypt-validate@vulnerabilities/api/src/Token.php:39 | not-real | FP → TP | REGRESS | Low→High |
| php.lang.security.exec-use.exec-use@vulnerabilities/exec/source/medium.php:19 | real | NMD → TP | IMPROVE | Low→High |
| php.lang.security.injection.tainted-filename.tainted-filename@instructions.php:26 | not-real | FP → NMD | REGRESS | High→Low |
| php.lang.security.injection.tainted-filename.tainted-filename@vulnerabilities/view_source.php:67 | real | TP → NMD | REGRESS | High→Low |
| php.lang.security.injection.tainted-sql-string.tainted-sql-string@vulnerabilities/bac/source/medium.php:71 | real | TP → NMD | REGRESS | High→Low |
| php.lang.security.md5-loose-equality.md5-loose-equality@vulnerabilities/captcha/source/impossible.php:46 | not-real | TP → FP | IMPROVE | Low→High |
| php.lang.security.php-permissive-cors.php-permissive-cors@vulnerabilities/api/gen_openapi.php:6 | not-real | TP → FP | IMPROVE | High→High |
| php.lang.security.php-permissive-cors.php-permissive-cors@vulnerabilities/api/public/index.php:11 | not-real | TP → NMD | neutral | High→Low |

## Resource deltas

_Informational, non-gating — run-to-run variance is expected._

| metric            | Δ (cur - prev) |
|-------------------|----------------|
| cost              | +$0.00         |
| input tokens      | -98k           |
| output tokens     | -20k           |
| cache hit ratio   | +0.0pp         |
| model time        | -50.0s         |
| iterations (mean) | -0.38          |
| errors            | +0             |
| abstentions       | +3             |
