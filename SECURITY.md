# Security

This tool runs as root and changes firewall policy. Editable configuration is
parsed as literal data, not executed as shell code. Keep program files, accepted
runtime snapshots and the home-location registry root-owned. Keep editable home
files private. Granting access to settings or lists grants control over firewall
policy and who is trusted or blocked.

Local SSH monitoring reads authentication outcomes from the local journal, never
attempted passwords. Its runtime state contains source addresses and journal
cursors; keep it private along with settings, lists and logs. Runtime files and
home configuration must never be included in Git commits or release artifacts.

Report suspected vulnerabilities through this GitHub repository's private
security reporting facility when enabled. If unavailable, ask the maintainer
for a private reporting channel without posting exploit details or credentials
in a public issue. Do not attach production IP lists or authentication logs.

Only the latest published release is maintained. No external security audit is
claimed. Prefer key-based SSH access and keep FRP, OpenSSH, and your OS updated.
