## Local Pre-Commit Protection

SecretShield can check staged changes before Git creates a commit. The hook runs the existing Gitleaks detector, then applies SecretShield's Risk Engine and Policy Engine. `BLOCK` and `REVIEW` findings reject the commit; `WARN` and `ALLOW` findings let it proceed. The hook scans only relevant staged files, does not scan Git history, and never prints or stores raw secret values. GitHub Actions remains the second security layer and scans both current files and Git history.

The developer repository does not need SecretShield's source or dashboard. Clone SecretShield separately, then install its hook into the developer repository. On Windows PowerShell, from the developer repository:

```powershell
git clone https://github.com/anujgith/SecretShield.git ..\SecretShield
py ..\SecretShield\scripts\install_secretshield_hook.py
```

On Linux or macOS, from the developer repository:

```sh
git clone https://github.com/anujgith/SecretShield.git ../SecretShield
python3 ../SecretShield/scripts/install_secretshield_hook.py
```

Gitleaks must be installed locally. The hook uses `GITLEAKS_PATH` when set; otherwise it finds `gitleaks` on `PATH` or uses SecretShield's existing Windows default (`C:\gitleaks\gitleaks.exe`). If the SecretShield checkout is moved, run the installer again so the local hook points to its new location.

After installation, use the normal Git workflow:

```sh
git add .
git commit -m "Add feature"
```

When policy returns `REVIEW` or `BLOCK`, Git rejects the commit with exit code 1. A clean scan, or findings returning `WARN` or `ALLOW`, exits 0 and permits the commit. Scanner or configuration errors exit 2 and also prevent the commit. The local hook complements the reusable GitHub Actions security gate; it does not replace it.
