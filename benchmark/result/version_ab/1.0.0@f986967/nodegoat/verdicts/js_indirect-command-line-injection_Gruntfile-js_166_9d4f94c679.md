# js/indirect-command-line-injection @ Gruntfile.js:166

**Verdict:** TP · **Confidence:** Low (0.68) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 3

## Reasoning

The environment variable flows unchecked into a shell command executed by exec, providing a clear injection vector. No sanitisation is present, so an attacker who can set NODE_ENV can achieve command injection.

## Data flow

process.env.NODE_ENV (line 159) → finalEnv (line 159) → cmd (line 163) → cmd + "node artifacts/db-reset.js" (line 166) → exec (sink, line 166)

## Answers

1. 1. The source is the environment variable `process.env.NODE_ENV` on line 159, which can be set by the process launcher and is considered an external, attacker‑controllable input.
2. 2. Data flow: line 159 assigns `finalEnv = process.env.NODE_ENV || arg || "development"`; line 163 builds `cmd = (process.platform === "win32" ? "NODE_ENV=" + finalEnv + " & " : "NODE_ENV=" + finalEnv + " ");`; line 166 concatenates `cmd + "node artifacts/db-reset.js"` and passes the result to `exec`.
3. 3. No validation, sanitisation, or escaping is performed on `finalEnv` at any of these steps; the value is directly inserted into a shell command string.
4. 4. The sink is the call to `exec` on line 166, which executes the constructed command via the system shell. Because the command string contains unsanitised data, an attacker who controls `NODE_ENV` can inject additional shell commands (indirect command‑line injection).
5. 5. Neither Grunt nor Node's `exec` automatically escapes arguments; the code does not use safer alternatives like `execFile` or manual quoting, so there is no built‑in protection at the sink.
6. 6. The Grunt task runs with the privileges of the user who invokes `grunt`. An attacker who can influence the environment of that process (e.g., via CI configuration, container launch, or local access) can trigger this path.
7. 7. The concrete impact is Remote Code Execution (RCE) on the host machine, potentially allowing the attacker to run arbitrary commands and possibly gain higher privileges depending on the process user.
8. 8. The weakest link is the lack of any sanitisation/escaping of the environment variable before it is concatenated into a shell command (step 3). This unguarded concatenation directly leads to the unsafe `exec` call.
