# yaml.github-actions.security.run-shell-injection.run-shell-injection @ .github/workflows/docker-image.yml:29

**Verdict:** TP · **Confidence:** High (0.94) · **Truth:** not-real · **Grade:** FALSE-ALARM · **Iterations:** 3

## Reasoning

User‑controllable GitHub context fields flow through variables that are never quoted or safely escaped before being interpolated into a Bash command, providing a clear command‑injection vector.

## Data flow

github.repository_owner / github.ref / github.sha (lines 31‑36) → IMAGE_ID / VERSION / COMMIT (lines 31‑36) → docker buildx command (lines 41‑44)

## Answers

1. 1. **Source** – The data originates from the GitHub Actions context variables `${{ github.repository_owner }}`, `${{ github.ref }}` and `${{ github.sha }}` (used on lines 31, 33, 34, 36). These values are supplied by the workflow trigger (push or workflow_dispatch) and can be influenced by anyone who can create a branch/tag or trigger the workflow, i.e. an external user input.
2. 2. **Data‑flow trace** –
   - Line 31: `IMAGE_ID=ghcr.io/${{ github.repository_owner }}/dvwa`
   - Line 32: `IMAGE_ID=$(echo $IMAGE_ID | tr '[A-Z]' '[a-z]')` (lower‑case only)
   - Line 33: `VERSION=$(echo "${{ github.ref }}" | sed -e 's,.*/\(.*\),\1,')`
   - Line 34: `[[ "${{ github.ref }}" == "refs/tags/"* ]] && VERSION=$(echo $VERSION | sed -e 's/^v//')`
   - Line 35: `[ "$VERSION" == "master" ] && VERSION=latest`
   - Line 36: `COMMIT=$(echo "${{ github.sha }}" | cut -c 1-7)`
   - Lines 41‑44: `docker buildx build … --tag $IMAGE_ID:$VERSION … --tag $IMAGE_ID:$COMMIT …` – the variables are expanded unquoted in a shell command.
3. 3. **Validation / sanitisation** – No effective validation or escaping is performed. `tr`, `sed`, and `cut` only transform the string format; they do not remove or escape characters that are special to the shell (e.g., `;`, `&&`, backticks). Thus the sanitisation is insufficient for preventing command injection.
4. 4. **Sink** – The sink is the `docker buildx build` command on lines 41‑44, where `$IMAGE_ID`, `$VERSION`, and `$COMMIT` are interpolated into the command line without quoting. This allows an attacker‑controlled value to inject additional shell commands.
5. 5. **Framework protections** – GitHub Actions does not automatically quote `${{ … }}` values inside a `run:` step. The script is executed by Bash as‑is, so there is no built‑in protection for this pattern.
6. 6. **Privilege / authentication** – An attacker who can trigger the workflow (e.g., by pushing a branch/tag or using `workflow_dispatch`) and thereby control `github.ref` or `github.sha` can reach this code. This generally requires at least repository write access or the ability to open a pull request that runs the workflow, i.e., an authenticated contributor.
7. 7. **Security impact** – Successful injection yields arbitrary command execution on the CI runner (RCE). The attacker could read or exfiltrate secrets such as `GITHUB_TOKEN`, modify the built image, or compromise the runner environment.
8. 8. **Weakest link** – The lack of proper sanitisation/quoting of the interpolated GitHub context values before they are used in the shell command (steps 31‑44). No defensive transformation is applied, making the injection path exploitable.
