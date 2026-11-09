# Changelog

## [1.11.2] - 2026-11-09

### Fixed

- Delete orphaned postmeta with a MySQL-compatible single-table `DELETE` and correlated `NOT EXISTS` query, retaining the configured 500-row batch, custom table prefixes and existing Elementor/Divi exclusions.
- Protect WordPress root files, `wp-admin`, `wp-includes`/`WPINC`, and both supported `wp-config.php` locations from quarantine or permanent removal. Logical paths, resolved aliases and legacy quarantine records receive the same protection. Findings remain visible for manual review.
- Preserve a restored protected file if cleaning its quarantine copy fails; never roll back restoration by deleting the protected file.
- Reject symlinked or escaping conflicting-plugin trees before removal. Use guarded direct WordPress filesystem removal without running third-party uninstall scripts or hooks.

### Operator note

- Conflicting-plugin database settings and translations may remain because third-party uninstall code is intentionally bypassed. This patch constrains this plugin's destructive operations; it does not establish the cause of an earlier site incident or control unrelated software.
- Added cleanup and real-filesystem regressions. The orphan query was additionally tested against disposable MySQL 8.0.35 and 8.4.0 databases, with 55 checks passing on each.

## [1.11.1] - 2026-11-09

### Fixed

- Register the file-integrity update monitor in cron and CLI before their early returns.
- Recognise WordPress single-plugin completion metadata as well as bulk upgrades, preserving the scoped baseline and expected-update marker after legitimate background updates.

### Operator note

- This patch supersedes the initial 1.11.0 prerelease. Keep 1.11.0 unpromoted; use 1.11.1 for the migration canary and one-time bootstrap.

## [1.11.0] - 2026-11-09

### Added

- Public signed releases following HMDG's existing prerelease, canary and manual-promotion workflow.
- A native WordPress updater scoped to HMDG Security Pro, with no updater network, database or cookie work on ordinary visitor requests.
- Independent Ed25519 signing and fail-closed verification of the exact release bytes, plugin folder and declared version.
- Reproducible runtime-only packaging, version checks and behavioural regression tests.

### Changed

- Promoted newer releases can install through WordPress background updates once an existing site has received the one-time updater bootstrap.
- A dedicated Update URI prevents WordPress.org slug matching. Native installer rollback and activation handling are preserved, and failed-update emails remain enabled.

### Requirements

- WordPress 6.4+, PHP 8.2+, sodium and ZIP support. Prereleases do not install automatically; hosting restrictions, cron and API availability still apply.
