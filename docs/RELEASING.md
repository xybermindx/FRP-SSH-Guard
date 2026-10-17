# Release procedure

## First GitHub publication

Use a dedicated clone under your own Ubuntu user's home directory. Each Ubuntu
user should use their own GitHub login/SSH keys; avoid `sudo git`, `sudo gh`, and
sharing a working copy across users. Commit author settings and GitHub
authentication are separate.

For an initial publication from an untracked workspace, run `make dist` to create
a clean local source export. Extract it into that directory, then initialize Git:

```bash
tar -xzf frp-ssh-guard-0.0.4.tar.gz
cd frp-ssh-guard-0.0.4
git init -b main
git config --local user.name 'YOUR NAME'
git config --local user.email 'YOUR VERIFIED OR NOREPLY GITHUB EMAIL'
git add .
git diff --cached --stat
git commit -m 'Prepare FRP SSH Guard for public development and Debian deployment'
gh auth login --hostname github.com
gh auth status
gh repo create OWNER/FRP-Guard --public --source=. --remote=origin --push
```

Replace the owner and identity placeholders with the intended maintainer. Do not
initialize/push the directory containing private transfer archives without
reviewing the staged files. The release source archive contains development
files and empty templates, not deployment data or Git credentials.

Enable private vulnerability reporting in the repository settings and verify
that GitHub Actions is enabled. The existing MIT license is retained; update
its attribution and package maintainer metadata if appropriate.

## Versioned releases

1. Update `VERSION` (plain `MAJOR.MINOR.PATCH`) and `CHANGELOG.md`.
2. Run `make release` as an ordinary user. The build needs Python 3, Bash,
   GNU Make, and `dpkg-deb`; it does not install the tool or change the firewall.
3. Review `dist/`, run the disposable VM checklist in `ARCHITECTURE.md`, and
   record tested platforms and any limitations in release notes.
4. Commit the changes and push the branch. Require passing CI before tagging.
5. Create and push a matching tag:

   ```bash
   git tag -a "v$(cat VERSION)" -m "Release $(cat VERSION)"
   git push origin main
   git push origin "v$(cat VERSION)"
   ```

6. The release workflow runs validation and creates a **draft** GitHub release
   containing only the tested `.deb` and `SHA256SUMS`. GitHub automatically adds
   source ZIP/tar.gz links for the tag; do not upload duplicate source bundles.
   Review the notes and artifacts, then publish the draft on GitHub.

The workflow uses the repository's built-in `GITHUB_TOKEN` with release-write
permission only in the release job; no personal access token needs to be stored
in repository secrets. Re-running a tag workflow can update a draft's assets;
it refuses to overwrite a published release.

GitHub documents draft releases in its
[release management guide](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository).

## Public release layout

For v0.0.4, upload `frp-ssh-guard_0.0.4_all.deb` and `SHA256SUMS` only.
GitHub supplies **Source code (zip)** and **Source code (tar.gz)** from the tag.
Those automatic archives contain all tracked files; inspect the commit before
publishing and never commit live configuration, secrets, or deployment backups.
The checksum file covers uploaded installable packages, not GitHub-generated archives.

## Build details

- `make deb`: architecture-independent Debian binary package only.
- `make dist`: complete development source in tar.gz and zip formats.
- `make release`: tests, the Debian package, and a SHA256SUMS covering that package.
- `make clean`: remove generated `build/` and `dist/` directories.

Source export includes a fixed set of top-level files and development directories.
Only `.example` files are exported from `etc/`; live configuration, state, logs,
original transfer archives, and `.git` are excluded. Review additions inside
exported source directories before release.

`SOURCE_DATE_EPOCH` controls tar/deb timestamps. If absent, the builder uses a
fixed epoch so source-archive builds do not depend on Git history. ZIP timestamps
are fixed at 1980. Build twice with the same source, epoch, and toolchain to check
reproducibility; compressors from different distributions can produce different
binary output. Source archives include packaging/build scripts, so users can
rebuild the `.deb`. They are not Debian `.dsc` source packages or a signed APT
repository. Checksums detect changes but do not replace artifact signatures.

## Public project checklist

- Keep English `README.md` and Simplified Chinese `README.zh-CN.md` equivalent,
  with reciprocal language links and the actual release version.
- Complete `docs/VALIDATION.md` with observed results before publishing stable
  artifacts. Never present expected examples or configured CI as completed tests.
- Attach only the tested `.deb` and its `SHA256SUMS`. GitHub's automatic tag
  archives provide the full MIT-licensed runtime, packaging, build scripts, and tests.
- Check install, migration, source build, language links, and license links from
  the resulting repository and extracted archives.
- Retain user settings on upgrade; ship updated defaults as examples.
