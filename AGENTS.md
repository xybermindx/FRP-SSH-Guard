# Repository privacy requirements

Treat real deployment project, organization, machine and tunnel names, domains,
IP addresses, account details, logs and port mappings as private. Do not copy them
into source, templates, tests, documentation, commit messages or release notes.
Use invented port numbers and documentation-only IP ranges in public examples.
Do not publish real values in a denylist or in a test for the privacy checker.

Keep private regex rules outside the checkout or in the encrypted repository
Actions secret. Never display their contents in logs. Local archives under
`.private-artifacts/` are private backups and must not be committed or uploaded.

Follow CONTRIBUTING.md to install both privacy hooks in every new clone. Before
publishing changes, run the private source/history checks and `make test`. Builds
and release assets must pass the privacy scanner before upload. Do not bypass a
missing-private-rules failure on a maintainer push or release.

After a privacy history rewrite, use a fresh clone; merging an old branch can
restore removed information. Keep both language guides equivalent when editing
public examples. Privacy changes must not change a live server's firewall policy.
