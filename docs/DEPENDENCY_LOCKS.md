# Python dependency locks

The `requirements-*.txt` files are direct-dependency inputs. Their corresponding
`.lock` files pin the resolved transitive dependency versions and SHA-256 hashes.
Operator installs and CI must use the lock files with `pip install
--require-hashes`; do not install an input file directly for a controlled build.

| Lock file | Intended use |
|---|---|
| `requirements-key-management.lock` | Key-management utilities |
| `requirements-remote.lock` | Remote dashboard |
| `requirements-secure-transport.lock` | Secure transport |
| `requirements-runtime.lock` | Combined runtime feature set |
| `requirements-ci.lock` | Python CI tests and Bandit |
| `requirements-release-build.lock` | Python release bundle builder |

Locks are generated with pip-tools 7.6.2 using Python 3.12. To refresh them,
review the source inputs and resulting package/version changes, then regenerate
from a clean Python 3.12 environment:

```bash
python3.12 -m venv .venv-lock
.venv-lock/bin/python -m pip install pip-tools==7.6.2
.venv-lock/bin/pip-compile --generate-hashes --resolver=backtracking \
  --output-file=requirements-key-management.lock requirements-key-management.txt
.venv-lock/bin/pip-compile --generate-hashes --resolver=backtracking \
  --output-file=requirements-remote.lock requirements-remote.txt
.venv-lock/bin/pip-compile --generate-hashes --resolver=backtracking \
  --output-file=requirements-secure-transport.lock requirements-secure-transport.txt
.venv-lock/bin/pip-compile --generate-hashes --resolver=backtracking \
  --output-file=requirements-runtime.lock requirements-runtime.in
.venv-lock/bin/pip-compile --generate-hashes --resolver=backtracking \
  --output-file=requirements-ci.lock requirements-ci.in
.venv-lock/bin/pip-compile --allow-unsafe --generate-hashes --resolver=backtracking \
  --output-file=requirements-release-build.lock requirements-release-build.in
```

The hashes bind installation to artifacts advertised by the configured Python
package index; they do not independently establish publisher identity, source
review, build provenance, or package safety. The CI, feature, and release-build
locks do not include optional PyTorch/model-test dependencies, dynamically
installed application extras, native OS packages, or liboqs. Those remain
separate supply-chain work; a test skipped for an unavailable optional
dependency is not a pass for that capability.
