# Release procedure

## First GitHub publication

Use a dedicated clone under your own Ubuntu user's home directory. Each Ubuntu
user should use their own GitHub login/SSH keys; avoid `sudo git`, `sudo gh`, and
sharing a working copy across users. Commit author settings and GitHub
authentication are separate.

For an initial publication from an untracked workspace, run `make dist` to create
a clean local source export. Extract it into that directory, then initialize Git:

```bash
tar -xzf frp-ssh-guard-0.0.5.tar.gz
cd frp-ssh-guard-0.0.5
git init -b main
git config --local user.name 'YOUR NAME'
git config --local user.email 'YOUR VERIFIED OR NOREPLY GITHUB EMAIL'
git add .
git diff --cached --stat
git commit -m 'Prepare FRP-SSH-Guard for public development and Debian deployment'
gh auth login --hostname github.com
gh auth status
gh repo create OWNER/FRP-SSH-Guard --public --source=. --remote=origin --push
```

Replace the owner and identity placeholders with the intended maintainer. Do not
initialize/push the directory containing private transfer archives without
reviewing the staged files. The release source archive contains development
files and empty templates, not deployment data or Git credentials.

Enable private vulnerability reporting in the repository settings and verify
that GitHub Actions is enabled. The existing MIT license is retained; update
its attribution and package maintainer metadata if appropriate.

## Versioned releases

Release titles must be only the tag, for example `v0.0.6`; do not prefix the product name.
Public release names, download filenames and CLI output use the application
version. Debian metadata also includes a monotonically increasing internal
revision, so APT can upgrade earlier builds. Prefer a new application version
for future public releases; do not move a published tag without an explicit
maintainer-approved correction and complete revalidation.
1. For a new application version, update `VERSION` (plain `MAJOR.MINOR.PATCH`)
   and reset `PACKAGE_REVISION` to `1`. For a changed distribution of the same
   application version, run `make bump-revision` before building. Update
   `CHANGELOG.md` and commit both version files with the changes. Never distribute
   changed package contents with an already-distributed package version.
2. Run `make release` as an ordinary user. The build needs Python 3, Bash,
   GNU Make, and `dpkg-deb`; it does not install the tool or change the firewall.
3. Review `dist/`, run the disposable VM checklist in `VALIDATION.md`, and
   record tested platforms and any limitations in release notes.
4. Commit the changes and push the branch. Require passing CI before tagging.
5. Create and push a matching tag:

   ```bash
   release_tag="v$(cat VERSION)"  # first public release of this application version
   git tag -a "$release_tag" -m "Release $release_tag"
   git push origin main
   git push origin "$release_tag"
   ```

   Public tags always use `vMAJOR.MINOR.PATCH`. Internal Debian revisions are
   packaging metadata, not public release names. Normally publish subsequent
   changes under a new application version.

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

Release tag `v0.0.7` provides `frp-ssh-guard_0.0.7.deb` and `SHA256SUMS`.
The workflow requires the application tag, then independently checks Debian
metadata against `VERSION` and `PACKAGE_REVISION`.
It uses `docs/RELEASE-vVERSION.md` when present, otherwise `CHANGELOG.md`, for notes.
Existing v0.0.4, v0.0.5 and v0.0.6 tags and assets remain unchanged.
The filename omits the internal Debian revision and optional architecture suffix; Debian metadata remains
`Architecture: all` because the package contains architecture-independent scripts.

GitHub supplies **Source code (zip)** and **Source code (tar.gz)** from the tag.
Those automatic archives contain all tracked files; inspect the commit before
publishing and never commit live configuration, secrets, or deployment backups.
Check for real project/machine/tunnel names, domains, IP addresses, and deployment
port mappings in every distributed file, including tests and package documentation.
Use invented port examples and documentation-only IP addresses. Never upload
`.private-artifacts/` or old transfer backups. An ignore rule does not remove files
already committed; check Git history, tags, and existing release assets separately.
The checksum file covers uploaded installable packages, not GitHub-generated archives.

The build scans its source inputs and generated archives. Before publishing, run
`python3 scripts/privacy.py --history --require-private` and scan every intended
asset with `python3 scripts/privacy.py --require-private --artifacts PATH...`.
The Actions release workflow requires private rules stored in a repository secret
and scans the downloaded artifacts again before upload. See CONTRIBUTING.md for
local hooks and private-rule setup. Never place the rules in an archive or commit.

## Build details

- `make deb`: architecture-independent Debian binary package only.
- `make dist`: complete development source in tar.gz and zip formats.
- `make release`: tests, the Debian package, and a SHA256SUMS covering that package.
- `make bump-revision`: increment the tracked Debian revision for a changed distribution.
- `python3 scripts/build.py version`: print the full Debian version without building.
- `make clean`: remove generated `build/` and `dist/` directories.

`VERSION` and `PACKAGE_REVISION` produce the Debian version, currently `0.0.7-1`.
APT compares this metadata, not the filename. Revision `1` sorts after the older
bare `0.0.5`, and increasing revisions allow ordinary `sudo apt install ./FILE.deb`
upgrades. A new application version sorts after revisions of the previous one.
Builds never silently increment a revision: identical source and toolchain inputs
remain reproducible. Source archive names and the CLI use the application version;
the source archives include `PACKAGE_REVISION` so they rebuild the same package.

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
- Retain user values/comments on upgrade; back up the file before adding missing
  commented defaults. Never override a legacy port list with an empty selection.
  Test custom on/off values and idempotent reinstallation.
- Test active upgrades with `tests/vm-auto-upgrade.py`: apply updated rules and
  refresh monitor processes automatically while preserving accepted policy choices,
  pending edits, custom home files, jail scope/expiry, boot enablement and timer
  schedules. Do not restart timers or reload the systemd manager. Test inactive
  installs, trials, failure reporting, reinstallation and reboot restoration.
