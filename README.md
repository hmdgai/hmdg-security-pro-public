# HMDG Security Pro

WordPress security hardening maintained by [HMDG](https://hmdg.co.uk) for its managed sites.

- Version: `1.11.0` - see [CHANGELOG.md](CHANGELOG.md)
- WordPress: 6.4 or later
- PHP: 8.2 or later, with sodium and ZIP support for signed updates
- Plugin directory and entry point: `hmdg-security-pro/hmdg-security-pro.php`
- Licence: Proprietary; publication does not grant additional usage rights

This is the public runtime source and signed-release repository. Fleet inventories, hosting credentials and internal operational records stay in HMDG's private operations repository. No hosting or private-source access key is needed by this repository or installed sites.

## Release lifecycle

A version bump pushed to `main` runs PHP 8.2 syntax and behavioural checks, verifies all version declarations, and builds `hmdg-security-pro.zip`. The ZIP contains only the plugin bootstrap and PHP include files beneath the exact plugin directory. Ed25519 signing must match the public key embedded in the updater; a missing or incorrect signing key stops publication.

The workflow publishes a **prerelease** with its detached `.zip.sig` signature. Prereleases are excluded from `/releases/latest`, so publication alone does not update client sites. After a signed canary passes, an authorised operator promotes the release:

```sh
gh release edit v1.11.0 --repo hmdgai/hmdg-security-pro-public --latest --prerelease=false
```

Existing sites need a one-time signed bootstrap to install the updater. Later promoted versions use native WordPress background updates. Checks run in admin, cron and CLI contexts, with object-cache backoff; ordinary visitor requests do no updater work. No GitHub token is stored on sites. Cron availability, hosting policy, filesystem access and GitHub rate limits can delay or prevent updates.

The updater verifies the signature before inspecting the archive, then checks the fixed plugin folder and internal version against the requested release. Failed verification keeps the installed version. It does not delete the plugin directory or reactivate the plugin; native WordPress upgrade handling owns those operations. Failed-update notifications remain enabled.

## Checks

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
php tests/signed-release-updater.php
php -n tests/missing-release-primitives.php
python3 scripts/build_release.py --source . --output dist/hmdg-security-pro.zip
```

The first PHP test requires sodium and ZIP. The missing-primitives test deliberately runs without them. CI also lints every runtime, signing and test PHP file against the minimum supported PHP version.

## Signing and recovery

`HMDG_RELEASE_SIGNING_KEY` is a separate Security Pro Ed25519 seed stored only in the `release` environment, which accepts the public `main` branch. Fork and pull-request checks receive no signing key. Never commit the seed, reuse another plugin's key or replace an existing version's signed assets.

Promote only verified releases. If a promoted release needs reversing, publish the last known good code at a higher patch version, or use the private signed-bootstrap recovery procedure. Automatic updates reject version downgrades. Rotate the trust key in two stages: first deliver the replacement public key in a build signed by the existing key, then change the signing seed after the fleet has migrated.

This project is not listed on WordPress.org and is not offered with general public support. Report security concerns privately to HMDG.
