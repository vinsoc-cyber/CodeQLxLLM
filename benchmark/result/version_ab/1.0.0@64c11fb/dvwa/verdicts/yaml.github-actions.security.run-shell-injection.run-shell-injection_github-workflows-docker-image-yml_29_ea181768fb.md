# yaml.github-actions.security.run-shell-injection.run-shell-injection @ .github/workflows/docker-image.yml:29

**Verdict:** TP · **Confidence:** High (0.93) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 3

## Reasoning

The workflow directly injects the attacker‑controllable `github.ref` into a shell command without any sanitisation, creating a clear command‑injection vulnerability.

## Data flow

source (line 33, github.ref) → VERSION variable (lines 33‑35) → docker buildx command (lines 42‑43) where VERSION is interpolated

## Answers

1. 1. The source is the GitHub Actions context variable `${{ github.ref }}` (line 33). This value reflects the git ref (branch or tag) that triggered the workflow and can be supplied by any user who can push a ref or trigger `workflow_dispatch`.
2. 2. Data flow: line 33 reads `${{ github.ref }}` into the shell variable `VERSION` via `VERSION=$(echo "${{ github.ref }}" | sed -e 's,.*/\(.*\),\1,')`; line 34 may modify it (`[[ "${{ github.ref }}" == "refs/tags/"* ]] && VERSION=$(echo $VERSION | sed -e 's/^v//')`); line 35 may replace it with `latest` (`[ "$VERSION" == "master" ] && VERSION=latest`). The resulting `$VERSION` is then interpolated into the Docker command on lines 42‑43 (`--tag $IMAGE_ID:$VERSION`).
3. 3. No validation, sanitisation, or encoding is performed on `${{ github.ref }}`. The only transformations are `sed` and string comparison, which do not remove or escape shell‑special characters, so the data remains unsafe for command execution.
4. 4. The sink is the `docker buildx build` command (lines 41‑44). The unsanitised `$VERSION` variable is expanded in the command line, allowing command injection.
5. 5. GitHub Actions does not automatically escape `${{ }}` expressions inside a `run:` step. No framework‑level protection is applied here.
6. 6. An attacker needs the ability to create or push a ref (branch or tag) to the repository, i.e., a user with write/maintainer permissions (or the ability to trigger the workflow via `workflow_dispatch`). This is a privileged but not necessarily admin level.
7. 7. Successful exploitation yields remote code execution on the CI runner, enabling the attacker to steal secrets (e.g., `GITHUB_TOKEN`) and push malicious Docker images, leading to supply‑chain compromise and data theft.
8. 8. The weakest link is the lack of any sanitisation/validation of `${{ github.ref }}` before it is used in a shell command (line 33 → lines 42‑43). This allows attacker‑controlled characters to be interpreted by the shell.
