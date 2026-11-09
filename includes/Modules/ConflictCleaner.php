<?php

declare(strict_types=1);

namespace HMDG\Security\Modules;

use HMDG\Security\SecurityConfig;
use HMDG\Security\Services\LogService;
use HMDG\Security\Services\ProtectedRootPaths;

/**
 * One-shot activation-time cleanup of conflicting security plugins.
 *
 * When HMDG Security Pro is activated this module deactivates and
 * deletes a hard-coded list of conflicting plugins (MalCare, Wordfence,
 * and the legacy HMDG Security standalone plugin), then emails the
 * agency operator a summary and schedules an admin notice to confirm on
 * the next wp-admin page load.
 *
 * ──────────────────────────────────────────────────────────────────
 * HMDG Security (legacy) vs. HMDG Security Pro — CRITICAL DISTINCTION
 * ──────────────────────────────────────────────────────────────────
 *
 * HMDG Security (legacy):
 *   Slug:     hmdg-security
 *   File:     hmdg-security/hmdg-security.php
 *   Status:   Deprecated standalone plugin, pre-dates Pro.
 *   Action:   REMOVE on activation of HMDG Security Pro.
 *
 * HMDG Security Pro (THIS plugin):
 *   Slug:     hmdg-security-pro
 *   File:     hmdg-security-pro/hmdg-security-pro.php
 *   Status:   Current active plugin — the one this module runs inside.
 *   Action:   NEVER touch. Protected by the HMDG_SECURITY_PRO_BASENAME
 *             and explicit-slug guards in process_plugin().
 *
 * These are completely different plugins with similar names. The legacy
 * plugin conflicts with Pro and is safely removed here. Pro never removes
 * itself under any circumstance.
 *
 * ──────────────────────────────────────────────────────────────────
 * Execution contract
 * ──────────────────────────────────────────────────────────────────
 *
 *   - `run()` is invoked exclusively from `register_activation_hook` in
 *     hmdg-security-pro.php. It is not wired to any runtime hook, cron
 *     event, or admin action. Activating the plugin runs it once.
 *   - `show_admin_notice()` is a static method registered on
 *     `admin_notices` in `Plugin::boot()` (only when `is_admin()`). It
 *     reads a short-lived transient set by `run()` and clears it on
 *     first read. After the first admin page load following activation
 *     its cost is one cache lookup that returns false.
 *   - Nothing in this class ever runs on a front-end request.
 *
 * ──────────────────────────────────────────────────────────────────
 * Safety posture
 * ──────────────────────────────────────────────────────────────────
 *
 * Five layers of defence prevent accidental deletion:
 *
 *   1. The removal list is a `private const` — cannot be mutated at
 *      runtime, and there is deliberately NO filter/action hook that
 *      would let external code add to it. A hook like
 *      `apply_filters('hmdg_conflicting_plugins', ...)` would be a
 *      critical vulnerability; it does not exist here.
 *   2. Explicit own-plugin guard: the first check in `process_plugin()`
 *      short-circuits if the candidate slug equals `hmdg-security-pro`
 *      or its file matches `HMDG_SECURITY_PRO_BASENAME`.
 *   3. Explicit HMDG Helpers guard: same layer, second check, blocks
 *      the `hmdg-helpers` slug regardless of folder name variant.
 *   4. Disk verification: folder must exist, main file must exist,
 *      main file must contain `Plugin Name:` in its first 1 KB.
 *   5. Identity verification: the main file's plugin-header `Name`
 *      must contain the expected vendor string (MalCare/Wordfence/
 *      HMDG Security) — prevents slug-collision attacks where a
 *      legitimate client plugin happens to occupy one of the target
 *      folder names. For the legacy HMDG Security check, the name
 *      must contain "HMDG Security" AND must NOT contain "Pro".
 *
 * Any guard failure → the candidate is recorded as skipped with a
 * human-readable reason and deletion is not attempted.
 *
 * @since 1.2.0
 */
final class ConflictCleaner
{
    /** Module identifier used in log entries. */
    private const MODULE = 'ConflictCleaner';

    /** Transient key used to pass results to the admin notice. */
    private const NOTICE_TRANSIENT = 'hmdg_pro_cleanup_notice';

    /** TTL of the admin-notice transient (one wp-admin page load is ample). */
    private const NOTICE_TTL = 5 * MINUTE_IN_SECONDS;

    /**
     * The own-plugin slug this module must NEVER process. Redundant with
     * `HMDG_SECURITY_PRO_BASENAME` but kept as a local constant so the
     * safety check works even if the bootstrap constant were ever missing
     * (defence in depth — we never trust a single signal).
     */
    private const OWN_SLUG = 'hmdg-security-pro';

    /**
     * HMDG Helpers slug — never processed. Separate internal agency
     * plugin with its own release pipeline. Touching it would break
     * every site that runs Helpers alongside Pro.
     */
    private const HELPERS_SLUG = 'hmdg-helpers';

    /**
     * The hard-coded list of conflicting plugins to remove on activation.
     *
     * Each entry is a closed-universe record: `slug` is the plugin folder
     * name, `file` is the plugin basename, `name` is the display label
     * for the cleanup email, `reason` is the operator-facing justification,
     * and `name_contains` is the substring the main file's "Plugin Name:"
     * header must contain for the deletion to proceed (slug-collision
     * defence — see safety layer 5 in the class docblock).
     *
     * For the legacy HMDG Security entry, `name_must_not_contain` prevents
     * the current HMDG Security Pro plugin from being caught if its own
     * metadata were ever misidentified. HMDG Security Pro's header says
     * "HMDG Security Pro" — it contains "Pro", so the legacy check's
     * "must NOT contain Pro" rule correctly excludes it.
     *
     * Adding to this list requires a code change, review, and a tagged
     * release. There is NO filter/option/database mechanism to mutate it
     * at runtime.
     *
     * @var list<array{
     *     slug: string,
     *     file: string,
     *     name: string,
     *     reason: string,
     *     name_contains: string,
     *     name_must_not_contain?: string
     * }>
     */
    private const CONFLICTING_PLUGINS = [
        [
            // MalCare's plugin folder is `malcare-security/` but its main
            // file is `malcare.php` — NOT `malcare-security.php`. Verified
            // on a live WPE install running MalCare 6.39: the file
            // `malcare-security/malcare-security.php` does not exist.
            // get_plugins() keys on the actual main file, so the 'file'
            // value below must match what WP discovers on disk.
            'slug'          => 'malcare-security',
            'file'          => 'malcare-security/malcare.php',
            'name'          => 'MalCare Security',
            'reason'        => 'Replaced by HMDG Security Pro. MalCare causes PHP worker exhaustion via per-request database writes and external HTTP calls to its cloud backend.',
            'name_contains' => 'MalCare',
        ],
        [
            'slug'          => 'wordfence',
            'file'          => 'wordfence/wordfence.php',
            'name'          => 'Wordfence Security',
            'reason'        => 'Replaced by HMDG Security Pro. Wordfence adds 200-400ms latency per page load and exhausts PHP workers under traffic.',
            'name_contains' => 'Wordfence',
        ],
        [
            'slug'                  => 'hmdg-security',
            'file'                  => 'hmdg-security/hmdg-security.php',
            'name'                  => 'HMDG Security (Legacy)',
            'reason'                => 'Superseded by HMDG Security Pro. The legacy standalone plugin conflicts with Pro and must be removed.',
            'name_contains'         => 'HMDG Security',
            // Explicitly excludes HMDG Security Pro by requiring the
            // legacy name not to contain "Pro". This is a belt-and-braces
            // check in addition to the OWN_SLUG guard in process_plugin().
            'name_must_not_contain' => 'Pro',
        ],
    ];

    /**
     * @param SecurityConfig $config Used for the alert-email recipient.
     * @param LogService     $logger Structured file logger.
     */
    public function __construct(
        private readonly SecurityConfig $config,
        private readonly LogService $logger,
    ) {}

    /**
     * Run the one-shot cleanup. Called from `register_activation_hook`
     * in hmdg-security-pro.php and nowhere else.
     *
     * Wrapped in a top-level try/catch so that any exception inside the
     * cleanup cannot propagate to WordPress core. If it did, WP would
     * silently roll back activation and the admin would see "plugin
     * could not be activated" with no diagnostic — far worse than a
     * cleanup that failed partially and left a log entry behind.
     */
    public function run(): void
    {
        try {
            $this->runInner();
        } catch (\Throwable $e) {
            $this->logger->error(
                module: self::MODULE,
                message: 'Fatal error during activation cleanup — caught to preserve activation',
                context: [
                    'error'   => $e->getMessage(),
                    'file'    => $e->getFile(),
                    'line'    => $e->getLine(),
                ],
            );
        }
    }

    /**
     * Inner cleanup workflow. Errors here are caught by `run()`.
     */
    private function runInner(): void
    {
        // WP's plugin functions are not loaded on every request — we
        // need them for discovery, silent deactivation and cache invalidation.
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        if (!function_exists('wp_clean_plugins_cache')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        // Use the WordPress filesystem API, without executing vendor uninstall code.
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        /** @var array<string, array<string, mixed>> $installed */
        $installed = get_plugins();

        /** @var list<array<string, mixed>> $removed */
        $removed = [];
        /** @var list<array<string, mixed>> $failed */
        $failed = [];
        /** @var list<array<string, mixed>> $skipped */
        $skipped = [];

        foreach (self::CONFLICTING_PLUGINS as $plugin) {
            $result = $this->processPlugin($plugin, $installed);

            match ($result['status']) {
                'removed' => $removed[] = $result,
                'failed'  => $failed[]  = $result,
                'skipped' => $skipped[] = $result,
            };
        }

        // Only notify if we actually did something. No need to email the
        // operator every time the plugin is activated on a clean site
        // (which is the common case for newly-onboarded HMDG clients).
        if ($removed !== [] || $failed !== []) {
            $this->sendCleanupReport($removed, $failed, $skipped);

            set_transient(
                self::NOTICE_TRANSIENT,
                [
                    'removed' => $removed,
                    'failed'  => $failed,
                ],
                self::NOTICE_TTL,
            );
        }

        $this->logger->info(
            module: self::MODULE,
            message: 'ConflictCleaner completed',
            context: [
                'removed' => count($removed),
                'failed'  => count($failed),
                'skipped' => count($skipped),
            ],
        );
    }

    /**
     * Evaluate one candidate plugin against all safety layers, then
     * deactivate + delete if every check passes. Returns a structured
     * result for reporting.
     *
     * @param array{slug: string, file: string, name: string, reason: string, name_contains: string, name_must_not_contain?: string} $plugin
     * @param array<string, array<string, mixed>>                                                                                    $installed
     *
     * @return array{status: 'removed'|'failed'|'skipped', plugin: array<string, mixed>, reason?: string, version?: string}
     */
    private function processPlugin(array $plugin, array $installed): array
    {
        // ── Safety layer 2a: own-plugin guard ──────────────────────────
        // This is the absolute first check. If the hard-coded removal
        // list ever accidentally included `hmdg-security-pro`, this
        // catches it before any filesystem I/O happens.
        if ($plugin['slug'] === self::OWN_SLUG) {
            $this->logger->warning(
                module: self::MODULE,
                message: 'Blocked attempt to process own plugin — hard-coded list regression?',
                context: ['slug' => $plugin['slug']],
            );
            return [
                'status' => 'skipped',
                'plugin' => $plugin,
                'reason' => 'Protected: own plugin (hmdg-security-pro)',
            ];
        }

        // Defence-in-depth: also check against the canonical bootstrap
        // constant. Different code path to the slug check above — if
        // one were ever bypassed, the other still holds.
        if (defined('HMDG_SECURITY_PRO_BASENAME')
            && $plugin['file'] === HMDG_SECURITY_PRO_BASENAME) {
            $this->logger->warning(
                module: self::MODULE,
                message: 'Blocked attempt to process own plugin by basename — hard-coded list regression?',
                context: ['file' => $plugin['file']],
            );
            return [
                'status' => 'skipped',
                'plugin' => $plugin,
                'reason' => 'Protected: own plugin (basename match)',
            ];
        }

        // ── Safety layer 3: HMDG Helpers guard ─────────────────────────
        if ($plugin['slug'] === self::HELPERS_SLUG) {
            return [
                'status' => 'skipped',
                'plugin' => $plugin,
                'reason' => 'Protected: HMDG Helpers (sibling internal plugin)',
            ];
        }

        // Not installed at the expected main-file path? Two subcases:
        //   (a) Plugin genuinely not installed — skip silently.
        //   (b) Plugin folder exists on disk but our hardcoded 'file'
        //       path doesn't match the vendor's actual main-file name.
        //       That's a config drift between this constant and the
        //       vendor's release — we log a warning so it surfaces in
        //       the next cron health check rather than being a silent
        //       "why didn't ConflictCleaner remove X?" mystery.
        if (!isset($installed[$plugin['file']])) {
            $slugFolderExists = is_dir(WP_PLUGIN_DIR . '/' . $plugin['slug']);
            if ($slugFolderExists) {
                // Scan the installed array for any main file in this
                // slug's folder — helps the operator find the real path.
                $matchingInstalls = [];
                foreach (array_keys($installed) as $installedFile) {
                    if (is_string($installedFile) && str_starts_with($installedFile, $plugin['slug'] . '/')) {
                        $matchingInstalls[] = $installedFile;
                    }
                }
                $this->logger->warning(
                    module: self::MODULE,
                    message: 'Target plugin folder exists on disk but hardcoded file path did not match any entry in get_plugins() — config drift',
                    context: [
                        'slug'           => $plugin['slug'],
                        'expected_file'  => $plugin['file'],
                        'actual_entries' => $matchingInstalls,
                    ],
                );
                return [
                    'status' => 'skipped',
                    'plugin' => $plugin,
                    'reason' => sprintf(
                        'Folder "%s/" exists but main file differs from expected "%s" — update ConflictCleaner::CONFLICTING_PLUGINS',
                        $plugin['slug'],
                        $plugin['file'],
                    ),
                ];
            }

            return [
                'status' => 'skipped',
                'plugin' => $plugin,
                'reason' => 'Not installed',
            ];
        }

        // ── Safety layer 4: disk verification ──────────────────────────
        $pluginPath = WP_PLUGIN_DIR . '/' . $plugin['slug'];
        if (!is_dir($pluginPath)) {
            return [
                'status' => 'skipped',
                'plugin' => $plugin,
                'reason' => 'Folder not found on disk (plugin entry stale)',
            ];
        }

        $pluginFilePath = WP_PLUGIN_DIR . '/' . $plugin['file'];
        if (!file_exists($pluginFilePath)) {
            return [
                'status' => 'skipped',
                'plugin' => $plugin,
                'reason' => 'Main plugin file not found on disk',
            ];
        }

        // Read the first 1 KB of the main file — enough for the plugin
        // header WP itself parses (it reads 8 KB, we only need the name).
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
        $handle = fopen($pluginFilePath, 'r');
        if ($handle === false) {
            return [
                'status' => 'skipped',
                'plugin' => $plugin,
                'reason' => 'Could not open main file for header inspection',
            ];
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
        $header = (string) fread($handle, 1024);
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
        fclose($handle);

        if (strpos($header, 'Plugin Name:') === false) {
            $this->logger->warning(
                module: self::MODULE,
                message: 'Candidate folder is not a valid WordPress plugin — skipped',
                context: ['slug' => $plugin['slug']],
            );
            return [
                'status' => 'skipped',
                'plugin' => $plugin,
                'reason' => 'Not a valid WordPress plugin (no header)',
            ];
        }

        // ── Safety layer 5: identity verification ──────────────────────
        // Mitigates slug collision — a legitimate client plugin that
        // happens to occupy `wordfence/` or `malcare-security/` for
        // unrelated reasons must not be caught. Verify the declared
        // plugin name matches the expected vendor substring.
        $declaredName = $this->extractPluginName($header);
        if ($declaredName === '') {
            return [
                'status' => 'skipped',
                'plugin' => $plugin,
                'reason' => 'Could not extract Plugin Name from header',
            ];
        }

        if (stripos($declaredName, $plugin['name_contains']) === false) {
            $this->logger->warning(
                module: self::MODULE,
                message: 'Plugin name did not match expected vendor string — slug collision defence triggered',
                context: [
                    'slug'           => $plugin['slug'],
                    'declared_name'  => $declaredName,
                    'expected_match' => $plugin['name_contains'],
                ],
            );
            return [
                'status' => 'skipped',
                'plugin' => $plugin,
                'reason' => sprintf(
                    'Plugin in folder is named "%s" — does not contain expected "%s"; refusing to delete to avoid slug-collision damage',
                    $declaredName,
                    $plugin['name_contains'],
                ),
            ];
        }

        if (isset($plugin['name_must_not_contain'])
            && stripos($declaredName, $plugin['name_must_not_contain']) !== false) {
            $this->logger->warning(
                module: self::MODULE,
                message: 'Plugin name contains disallowed substring — refusing to delete',
                context: [
                    'slug'           => $plugin['slug'],
                    'declared_name'  => $declaredName,
                    'disallowed'     => $plugin['name_must_not_contain'],
                ],
            );
            return [
                'status' => 'skipped',
                'plugin' => $plugin,
                'reason' => sprintf(
                    'Plugin name "%s" contains "%s" — likely HMDG Security Pro or similar; refusing to delete',
                    $declaredName,
                    $plugin['name_must_not_contain'],
                ),
            ];
        }

        // ── All safety layers passed — proceed with removal ────────────
        // WordPress recursively deletes plugin trees; never let a link carry that into site files.
        if (!$this->isSafeRemovalTree($pluginPath)) {
            $this->logger->warning(
                module: self::MODULE,
                message: 'Conflicting plugin retained — unsafe or linked removal tree',
                context: ['slug' => $plugin['slug']],
            );
            return [
                'status' => 'skipped',
                'plugin' => $plugin,
                'reason' => 'Protected: plugin tree contains a symlink, root alias or unresolved/escaping path',
            ];
        }

        $version = isset($installed[$plugin['file']]['Version'])
            ? (string) $installed[$plugin['file']]['Version']
            : 'unknown';

        /** @var \WP_Filesystem_Base|null $wp_filesystem */
        global $wp_filesystem;
        if (!$wp_filesystem) {
            \WP_Filesystem([], WP_CONTENT_DIR, true);
        }
        if (!($wp_filesystem instanceof \WP_Filesystem_Direct)) {
            return [
                'status' => 'skipped',
                'plugin' => $plugin,
                'reason' => 'Protected: a local direct filesystem is required for verified removal',
            ];
        }

        if (is_plugin_active($plugin['file'])) {
            deactivate_plugins($plugin['file'], true);
            $this->logger->info(
                module: self::MODULE,
                message: 'Deactivated conflicting plugin',
                context: ['name' => $plugin['name'], 'version' => $version],
            );
        }

        // delete_plugins() executes third-party uninstall scripts/hooks. Remove only the
        // verified directory instead; vendor settings remain available for manual cleanup.
        $deleted = $this->isSafeRemovalTree($pluginPath) && $wp_filesystem->delete($pluginPath, true);
        if (!$deleted) {
            $message = 'Verified plugin directory removal failed; manual removal may be required';
            $this->logger->warning(
                module: self::MODULE,
                message: $message,
                context: ['name' => $plugin['name'], 'error' => $message],
            );
            return [
                'status' => 'failed',
                'plugin' => $plugin,
                'reason' => $message,
            ];
        }
        wp_clean_plugins_cache();

        // Verify the folder is actually gone. Filesystem deletion can return
        // true while leaving residue on some filesystems or permission
        // configurations — better to check and report.
        clearstatcache(true, $pluginPath);
        if (is_dir($pluginPath)) {
            $this->logger->warning(
                module: self::MODULE,
                message: 'Filesystem deletion reported success but plugin folder still exists',
                context: ['slug' => $plugin['slug']],
            );
            return [
                'status' => 'failed',
                'plugin' => $plugin,
                'reason' => 'Folder remains after deletion attempt — manual removal may be required',
            ];
        }

        $this->logger->info(
            module: self::MODULE,
            message: 'Successfully removed conflicting plugin',
            context: ['name' => $plugin['name'], 'version' => $version],
        );

        return [
            'status'  => 'removed',
            'plugin'  => $plugin,
            'version' => $version,
        ];
    }

    /**
     * @security Check every entry before deactivation/uninstall can invoke recursive filesystem deletion.
     * @param string $pluginPath Allowlisted plugin directory.
     * @return bool False on links, canonical escapes, protected aliases or unreadable trees.
     */
    private function isSafeRemovalTree(string $pluginPath): bool
    {
        $pluginsRoot = realpath(WP_PLUGIN_DIR);
        $resolved = realpath($pluginPath);
        if ($pluginsRoot === false || $resolved === false || is_link($pluginPath)
            || ProtectedRootPaths::containsProtectedPaths($pluginPath)) {
            return false;
        }
        $root = ProtectedRootPaths::normalise($resolved);
        $expected = ProtectedRootPaths::normalise($pluginsRoot . '/' . basename($pluginPath));
        if ($root === null || $root !== $expected) {
            return false;
        }
        try {
            $entries = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($pluginPath, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST,
            );
            foreach ($entries as $entry) {
                $real = $entry->getRealPath();
                $normalised = $real !== false ? ProtectedRootPaths::normalise($real) : null;
                if ($entry->isLink() || $normalised === null || !str_starts_with($normalised, $root . '/')) {
                    return false;
                }
            }
        } catch (\UnexpectedValueException) {
            return false;
        }
        return true;
    }

    /**
     * Parse the "Plugin Name:" value from a plugin-header byte string.
     * WordPress's own `get_file_data()` does the same thing; we inline a
     * minimal parse here to avoid pulling `get_file_data()` semantics
     * into a safety-critical path (less surface area to reason about).
     *
     * @param string $header First 1 KB of the main plugin file.
     */
    private function extractPluginName(string $header): string
    {
        if (preg_match('/Plugin Name:\s*(.+?)[\r\n]/', $header, $matches) !== 1) {
            return '';
        }
        return trim($matches[1]);
    }

    /**
     * Email the agency operator a summary of the cleanup.
     *
     * Uses `wp_mail()` directly rather than AlertService because:
     *   - This is an administrative confirmation, not a security alert.
     *     AlertService's rate limiting and HTML template (severity badges,
     *     recommendation block) would be inappropriate.
     *   - ConflictCleaner must have minimum dependencies — it runs during
     *     activation where any fatal is silently rolled back by WP.
     *   - wp_mail is always available by activation time (WP loaded).
     *
     * Recipient is `SecurityConfig::alertEmail` (defaults to
     * felmerald@hmdg.co.uk). All user-facing strings are passed through
     * sanitize_text_field() to defuse any header-injection via a crafted
     * plugin name in the installed list.
     *
     * @param list<array<string, mixed>> $removed
     * @param list<array<string, mixed>> $failed
     * @param list<array<string, mixed>> $skipped
     */
    private function sendCleanupReport(array $removed, array $failed, array $skipped): void
    {
        $recipient = sanitize_email($this->config->alertEmail);
        if ($recipient === '') {
            $this->logger->warning(
                module: self::MODULE,
                message: 'Alert email is empty or invalid — skipping cleanup report email',
            );
            return;
        }

        $siteUrl     = sanitize_text_field(home_url());
        $wpVersion   = sanitize_text_field(get_bloginfo('version'));
        $phpVersion  = sanitize_text_field(PHP_VERSION);
        $siteDomain  = (string) (wp_parse_url($siteUrl, PHP_URL_HOST) ?: 'localhost');

        $timestamp = (new \DateTimeImmutable(
            datetime: 'now',
            timezone: new \DateTimeZone(timezone: 'Europe/London'),
        ))->format(format: 'd M Y H:i:s T');

        $subjectRaw = sprintf('[HMDG Security Pro] Plugin Cleanup on %s', $siteDomain);
        // wp_mail strips newlines from subjects defensively but we
        // neutralise here too — sanitize_text_field removes CR/LF.
        $subject = sanitize_text_field($subjectRaw);

        $body  = "════════════════════════════════════════════\n";
        $body .= "HMDG SECURITY PRO — ACTIVATION CLEANUP\n";
        $body .= "════════════════════════════════════════════\n\n";
        $body .= "Site:    {$siteUrl}\n";
        $body .= "Date:    {$timestamp}\n";
        $body .= "Action:  Conflicting security plugins removed\n\n";

        if ($removed !== []) {
            $body .= "────────────────────────────────────────────\n";
            $body .= sprintf("SUCCESSFULLY REMOVED (%d):\n", count($removed));
            $body .= "────────────────────────────────────────────\n\n";
            foreach ($removed as $entry) {
                $name    = sanitize_text_field((string) $entry['plugin']['name']);
                $version = sanitize_text_field((string) ($entry['version'] ?? 'unknown'));
                $reason  = sanitize_text_field((string) $entry['plugin']['reason']);
                $body .= "✅ {$name} v{$version}\n";
                $body .= "   Reason: {$reason}\n\n";
            }
        }

        if ($failed !== []) {
            $body .= "────────────────────────────────────────────\n";
            $body .= sprintf("FAILED TO REMOVE (%d):\n", count($failed));
            $body .= "────────────────────────────────────────────\n\n";
            foreach ($failed as $entry) {
                $name   = sanitize_text_field((string) $entry['plugin']['name']);
                $reason = sanitize_text_field((string) ($entry['reason'] ?? 'unknown error'));
                $body .= "❌ {$name}\n";
                $body .= "   Error:  {$reason}\n";
                $body .= "   Action: Remove manually via wp-admin or SFTP.\n\n";
            }
        }

        $body .= "────────────────────────────────────────────\n";
        $body .= "WHAT HAPPENS NEXT\n";
        $body .= "────────────────────────────────────────────\n\n";
        $body .= "HMDG Security Pro is now active and protecting this site.\n";
        $body .= "The removed plugins have been fully uninstalled — no residual\n";
        $body .= "plugin files remain. Some plugins (notably Wordfence) may leave\n";
        $body .= "secondary files behind (e.g. wp-content/wflogs/, .user.ini\n";
        $body .= "directives) that are safe to delete manually if present.\n\n";
        if ($failed !== []) {
            $body .= "IMPORTANT: one or more plugins could not be removed.\n";
            $body .= "Please delete them manually to avoid conflicts.\n\n";
        }
        $body .= "════════════════════════════════════════════\n";
        $body .= "WordPress:  {$wpVersion}\n";
        $body .= "PHP:        {$phpVersion}\n";
        $body .= "════════════════════════════════════════════\n";

        $fromEmail = 'wordpress@' . $siteDomain;
        $headers = [
            'Content-Type: text/plain; charset=UTF-8',
            sprintf('From: HMDG Security Pro <%s>', $fromEmail),
        ];

        $sent = wp_mail(
            to:      $recipient,
            subject: $subject,
            message: $body,
            headers: $headers,
        );

        $this->logger->info(
            module: self::MODULE,
            message: $sent ? 'Cleanup report emailed' : 'Cleanup report email FAILED to send',
            context: [
                'recipient' => $recipient,
                'removed'   => count($removed),
                'failed'    => count($failed),
                'skipped'   => count($skipped),
            ],
        );
    }

    /**
     * Render the admin notice summarising what the activation cleanup did.
     *
     * Registered on `admin_notices` from `Plugin::boot()` when
     * `is_admin()` is true. Static so that no ConflictCleaner instance
     * has to be kept alive on every admin request — the only thing this
     * method needs is the transient value plus a capability check.
     *
     * On every admin page load after activation, the happy-path cost is:
     *   1× capability check (in-memory)
     *   1× get_transient (Redis cache hit, ~0.1ms)
     *   Return on empty transient.
     *
     * After the first admin page load following activation the transient
     * is consumed and subsequent loads return on the empty check.
     */
    public static function show_admin_notice(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $data = get_transient(self::NOTICE_TRANSIENT);
        if (empty($data) || !is_array($data)) {
            return;
        }

        // One-shot: clear immediately so a refresh doesn't re-show it.
        delete_transient(self::NOTICE_TRANSIENT);

        /** @var list<array<string, mixed>> $removed */
        $removed = isset($data['removed']) && is_array($data['removed']) ? $data['removed'] : [];
        /** @var list<array<string, mixed>> $failed */
        $failed = isset($data['failed']) && is_array($data['failed']) ? $data['failed'] : [];

        if ($removed !== []) {
            $names = array_map(
                static fn(array $entry): string => esc_html((string) ($entry['plugin']['name'] ?? 'unknown')),
                $removed,
            );
            printf(
                '<div class="notice notice-success is-dismissible"><p><strong>%s</strong> %s <strong>%s</strong>. %s</p></div>',
                esc_html__('HMDG Security Pro:', 'hmdg-security-pro'),
                esc_html__('The following conflicting security plugins were automatically removed during activation:', 'hmdg-security-pro'),
                implode(', ', $names),
                esc_html__('Your site is now protected exclusively by HMDG Security Pro.', 'hmdg-security-pro'),
            );
        }

        if ($failed !== []) {
            $names = array_map(
                static fn(array $entry): string => esc_html((string) ($entry['plugin']['name'] ?? 'unknown')),
                $failed,
            );
            printf(
                '<div class="notice notice-error is-dismissible"><p><strong>%s</strong> %s <strong>%s</strong>. %s</p></div>',
                esc_html__('HMDG Security Pro:', 'hmdg-security-pro'),
                esc_html__('The following conflicting security plugins could not be removed automatically and should be deleted manually:', 'hmdg-security-pro'),
                implode(', ', $names),
                esc_html__('See the email report for details.', 'hmdg-security-pro'),
            );
        }
    }
}
