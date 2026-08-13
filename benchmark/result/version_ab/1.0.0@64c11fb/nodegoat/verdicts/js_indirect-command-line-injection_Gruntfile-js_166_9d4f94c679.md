# js/indirect-command-line-injection @ Gruntfile.js:166

**Verdict:** TP · **Confidence:** High (0.93) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 3

## Reasoning

The code constructs a shell command from an attacker‑controllable environment variable and passes it directly to Node's `exec` without any sanitization, resulting in a clear command‑injection vulnerability.

## Data flow

process.env.NODE_ENV (line 159) → finalEnv (line 159) → cmd (line 163) → exec argument (line 166)

## Answers

1. 1. The source is the environment variable `process.env.NODE_ENV` (line 159). This is attacker‑controllable if the process environment can be set before the Grunt task runs.
2. 2. Data flow: line 159 assigns `finalEnv = process.env.NODE_ENV || arg || "development"`; line 163 builds `cmd = (process.platform === "win32" ? "NODE_ENV=" + finalEnv + " & " : "NODE_ENV=" + finalEnv + " ")`; line 166 concatenates `cmd + "node artifacts/db-reset.js"` and passes the resulting string to `exec`.
3. 3. No validation, sanitization, or encoding is performed on `finalEnv` or `cmd` in the shown code. The additional context confirms that `exec` is not defined in the project scope, so it is the standard Node.js `child_process.exec` which does not perform any escaping of its command argument.
4. 4. The sink is the call to `exec` on line 166. `exec` runs the supplied command string in a shell, so any injected characters (e.g., `&&`, `;`, `|`) become executable commands.
5. 5. Neither Node's `exec` nor Grunt provides automatic escaping for the command string. The code does not use safer alternatives such as `execFile` or argument arrays, so there is no built‑in protection.
6. 6. The `db-reset` task is registered without any authentication or privilege checks; any user who can invoke the Grunt task (e.g., via `grunt db-reset` locally or through a CI pipeline) can trigger the vulnerable path. Effectively unauthenticated within the process.
7. 7. An attacker who can control `NODE_ENV` can achieve remote code execution on the host running the Grunt process, potentially leading to full system compromise, data theft, or denial‑of‑service.
8. 8. The weakest link is the lack of any sanitization or validation of the environment variable before it is interpolated into a shell command (steps 159 → 163 → 166).
