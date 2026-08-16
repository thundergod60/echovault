# Pushing EchoVault to GitHub (and building the driver in the cloud)

This project lives inside a larger git repo that covers your whole Desktop,
so it gets its **own** repo. Everything below is free and touches nothing on
your machine except the project folder. A `.gitignore` is already in place
to keep binaries and junk out.

## 1. Create a fresh repo just for this project

Open a terminal **inside** this folder
(`C:\Users\Lenovo\Desktop\password manager`) and run:

```bat
git init
git add .
git status
```

Check the `git status` list: it should show source files only (no
`EchoVault.exe`, no `*.exe`, no `.freebuff`). If anything unwanted slipped
in, add it to `.gitignore` and run `git add .` again.

Commit it:

```bat
git commit -m "EchoVault: source, driver prototype, build workflow"
```

## 2. Create the GitHub repo (private or public — both free)

1. Go to https://github.com/new
2. Name it `echovault` (or anything you like).
3. **Do NOT** tick "Add a README" / ".gitignore" / "license" (keep it empty).
4. Create repository.
5. Copy the "…or push an existing repository" commands and run them here:

```bat
git remote add origin https://github.com/YOURNAME/echovault.git
git branch -M main
git push -u origin main
```

(You'll authenticate once — a personal access token or the GitHub CLI.)

## 3. Build the driver in the cloud (free, zero risk)

1. On github.com, open the repo → **Actions** tab.
2. Left side: **Build EchoVault driver** → **Run workflow** → green button.
3. Wait ~10 minutes. The workflow installs the WDK on GitHub's machine,
   builds `EchoVaultFilter.sys`, and **runs the 48 gate-logic checks** on
   that fresh machine.
4. Open the finished run → **Artifacts** → download
   `EchoVaultFilter-sys` (a few dozen KB). That's the finished kernel
   driver — it does nothing on your machine until you explicitly load it.

Nothing in this whole guide can break your machine: no driver is ever
loaded here, no admin rights are needed, and no storage is used beyond the
tiny project files.
