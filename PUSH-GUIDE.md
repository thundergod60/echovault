# Building the EchoVault driver with GitHub Actions

EchoVault already has its own Git repository and GitHub remote:
`https://github.com/thundergod60/echovault`.

The cloud workflow is `.github/workflows/build-driver.yml`. It runs on a
GitHub-hosted Windows machine, restores Microsoft's WDK from NuGet, runs the
source-safety and user-mode driver tests, builds the x64 Release driver, checks
its embedded build tag, and publishes a SHA-256 hash with the artifact.

## Triggering a build

A push to `main` automatically starts a build when driver, shared-protocol,
WDK-package, or workflow files changed. You can also run it manually:

1. Open the repository on GitHub.
2. Open **Actions**.
3. Choose **Build EchoVault driver**.
4. Choose **Run workflow**, then **Run workflow** again.

Nothing is installed or loaded by the workflow. GitHub only compiles and
packages the files.

## Downloading the result

Open the completed workflow run and download the artifact named
`EchoVaultFilter-x64`. It contains:

- `EchoVaultFilter.sys`
- `EchoVaultFilter.inf`
- `EchoVaultFilter.sys.sha256`
- `build-info.txt` with the commit, run ID, safety build tag, and hash
- `EchoVaultFilter.binlog` for diagnosing compiler/linker problems

Confirm that the workflow is green and that the SHA-256 in `build-info.txt`
matches `EchoVaultFilter.sys.sha256` before treating the file as the result of
this source revision.

## Important limit

A successful GitHub build proves that the code compiles against the real WDK
and that the included user-mode logic tests pass. It does not execute the
kernel driver and cannot prove unload or runtime correctness. Keep the driver
demand-start and do not install it on the daily host merely because CI is
green. Runtime testing needs a disposable Windows test machine or a remote
test service that can be reset after a bugcheck.
