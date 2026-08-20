# Push DarkLayer SOC Center to GitHub

## 1. Create an empty repository on GitHub

Create a repository such as `DarkLayerSOC`. Do not add a README, `.gitignore`, or license on GitHub if you want to push this prepared repository without merge conflicts.

## 2. Verify sensitive files are excluded

From the project folder:

```bash
git init
git status --short
```

The repository should **not** contain a real `.env`, `data/soc.db`, `.venv`, collected logs, or SMTP credentials. The prepared `.gitignore` excludes these runtime files.

## 3. Make the first commit

```bash
git branch -M main
git add .
git status
git commit -m "Initial commit: DarkLayer SOC Center v1.2"
```

Review `git status` before committing. If a secret or local telemetry file appears, stop and remove it before pushing.

## 4. Connect the GitHub repository

HTTPS example:

```bash
git remote add origin https://github.com/YOUR_USERNAME/DarkLayerSOC.git
git push -u origin main
```

SSH example:

```bash
git remote add origin git@github.com:YOUR_USERNAME/DarkLayerSOC.git
git push -u origin main
```

## 5. Confirm GitHub Actions

After the push, open the repository's **Actions** tab. The included CI workflow compiles Python and runs both the SOC smoke test and live WebSocket stream test.

## Important

Never run `git add -f .env`, `git add -f data/`, or otherwise bypass `.gitignore` for credentials or collected telemetry. If a credential is accidentally pushed, revoke/rotate it even after deleting the Git history entry.
