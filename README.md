# SecretShield

SecretShield scans current repository files and staged Git changes with Gitleaks, then applies its Risk Engine and Policy Engine. The CLI and FastAPI share the current-file scan service. Findings and incidents contain metadata; raw secret values are not displayed or persisted.

## Install the CLI once

From a SecretShield checkout, install the package into the Python environment you use:

```powershell
py -m pip install -e .
```

The `secretshield` command can then be used from any repository; the SecretShield source does not need to be copied there. Install Gitleaks separately and make it available on `PATH`, or set `GITLEAKS_PATH` to its executable.

## Scan a repository

```sh
secretshield scan .
secretshield scan C:/path/to/repository
secretshield scan --staged
```

Current-file scans persist incidents in the SecretShield user data database (or the path configured by `SECRET_SHIELD_DATABASE_PATH`). Staged scans examine the Git index and apply the pre-commit policy without scanning unstaged working-tree changes.

## Protect a repository

Run these commands from the repository to protect:

```sh
secretshield protect
secretshield status
git add .
git commit -m "Add feature"
secretshield unprotect
```

The managed pre-commit hook invokes the installed CLI. It refuses to replace an unrecognized existing hook. `BLOCK` and `REVIEW` findings reject a commit, `WARN` and `ALLOW` let it proceed, and scanner errors also prevent the commit.

## Run the dashboard

From the project root, create the Python environment and install SecretShield if you have not already:

```powershell
py -m venv backend/.venv
backend\.venv\Scripts\python.exe -m pip install -e .
```

Then, in separate terminals, start the backend and frontend:

```powershell
backend\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --reload
```

```powershell
cd frontend
npm.cmd run dev
```

The dashboard reads incidents from the FastAPI database. Set `SECRET_SHIELD_DATABASE_PATH` for the backend if it should share the CLI's database.

Secret rotation in the dashboard is a **mock simulation only**. It makes no provider API calls and does not change credentials. Incident resolution continues to depend on the existing fingerprint rescan.

## GitHub Actions

The included workflow checks out full Git history (`fetch-depth: 0`) and scans current files and historical commits. In another workflow, check out the caller repository with `fetch-depth: 0` before invoking the composite action. The action runs SecretShield against the caller's `GITHUB_WORKSPACE`; it does not check out or scan the SecretShield source repository as the target.
