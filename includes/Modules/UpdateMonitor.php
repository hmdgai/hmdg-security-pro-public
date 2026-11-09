<?php

declare(strict_types=1);

namespace HMDG\Security\Modules;

use HMDG\Security\SecurityConfig;
use HMDG\Security\Services\LogService;
use HMDG\Security\Services\ObjectCacheService;

/**
 * Hooks WordPress' `upgrader_process_complete` action to auto-rebaseline
 * the file-integrity checksum set after a plugin, theme, or core update.
 *
 * Problem this solves:
 *   When WordPress (or an auto-updater) updates a plugin/theme/core, the
 *   on-disk files legitimately change. The next FileIntegrity scan then
 *   compares the new files against the stale SHA-256 baseline and emails
 *   a "Core File Modified" alert for every changed file. Across a 276-site
 *   fleet that translates to daily email floods — 100% false positives,
 *   confirmed clean by external Sucuri scans.
 *
 * What this module does:
 *   1. Listens to `upgrader_process_complete` (admin context only — WP
 *      fires it after any plugin/theme/core update via Plugin_Upgrader,
 *      Theme_Upgrader, or Core_Upgrader).
 *   2. Rebaselines the SHA-256 checksums for ONLY the updated paths
 *      (partial rebaseline — not the whole fleet-integrity file).
 *   3. Stamps a short-lived "recently updated" marker in the object cache
 *      for each updated path so that signature-based scanners
 *      (MalwareScanner) and the file-integrity alerter can suppress
 *      spurious alerts on the fresh code for the next 7 days.
 *
 * Design rules observed:
 *   - Object cache only. No `update_option`, no `set_transient`, no
 *     `$wpdb->` writes on any runtime path.
 *   - Admin context only — `upgrader_process_complete` never fires on
 *     anonymous front-end page loads. Plugin.php boots this module only
 *     when `is_admin()`, so a visitor request does not instantiate it.
 *   - No new HTTP calls. All work is local filesystem + hash_file +
 *     wp_cache_set.
 *
 * @since 1.3.2
 */
final class UpdateMonitor
{
    /** Module identifier used in log entries. */
    private const MODULE = 'UpdateMonitor';

    /**
     * Object-cache key prefix for "recently updated" markers.
     *
     * The full key is `self::RECENT_UPDATE_PREFIX . sha256($relativePath)`.
     * Sha256 of the path keeps keys bounded in size and free of path
     * separators that some cache backends treat oddly.
     */
    public const RECENT_UPDATE_PREFIX = 'hmdg_recent_update_';

    /**
     * TTL for "recently updated" markers (7 days in seconds).
     *
     * Long enough that the weekly integrity + malware scan runs at least
     * once inside the grace window. Short enough that a legitimate change
     * made later (e.g. manual edit) is not silently whitelisted forever.
     */
    public const RECENT_UPDATE_TTL = 7 * DAY_IN_SECONDS;

    /**
     * @param LogService         $logService    Structured file logger.
     * @param ObjectCacheService $cacheService  Object-cache wrapper.
     * @param SecurityConfig     $config        Immutable plugin config (reserved for future tuning).
     * @param FileIntegrity      $fileIntegrity FileIntegrity instance used for partial rebaseline.
     */
    public function __construct(
        private readonly LogService $logService,
        private readonly ObjectCacheService $cacheService,
        private readonly SecurityConfig $config,
        private readonly FileIntegrity $fileIntegrity,
    ) {}

    /**
     * Register the upgrader-complete hook.
     *
     * Priority 10 (explicit) with 2 accepted args: the WP_Upgrader
     * instance and the `$hookExtra` array that describes what was
     * updated. These are the standard parameters documented in
     * wp-admin/includes/class-wp-upgrader.php.
     */
    public function register(): void
    {
        add_action(
            'upgrader_process_complete',
            [$this, 'handleUpgraderComplete'],
            10,
            2,
        );
    }

    /**
     * Handle a completed upgrader run.
     *
     * `$hookExtra` payload shape (per WP core, since 3.7):
     *   - 'action'     => 'update' | 'install'
     *   - 'type'       => 'plugin' | 'theme' | 'core' | 'translation'
     *   - 'bulk'       => bool (true for multi-item updates)
     *   - 'plugins'    => list<string> of plugin basenames (when type=plugin)
     *   - 'themes'     => list<string> of theme stylesheets (when type=theme)
     *   - 'translations' => list<array> (when type=translation)
     *
     * We only act on type=plugin, type=theme, and type=core. Translations
     * update .mo files outside the PHP integrity set and are ignored.
     *
     * @param \WP_Upgrader        $upgrader   Upgrader instance (unused; kept for signature compat).
     * @param array<string,mixed> $hookExtra  Metadata about the completed update.
     *
     * @security Admin-only hook; this callback is only wired when the
     *           module is booted from Plugin::boot() in admin context.
     */
    public function handleUpgraderComplete(\WP_Upgrader $upgrader, array $hookExtra): void
    {
        // Hard-guard the callback even though the hook is admin-only — a
        // rogue `do_action('upgrader_process_complete', …)` call from
        // another plugin must not cause a rebaseline on a front-end request.
        if (!is_admin() && !(defined('WP_CLI') && WP_CLI) && !wp_doing_cron()) {
            return;
        }

        $type = isset($hookExtra['type']) && is_string($hookExtra['type'])
            ? $hookExtra['type']
            : '';

        if ($type === '') {
            return;
        }

        match ($type) {
            'plugin' => $this->handlePluginUpdate($hookExtra),
            'theme'  => $this->handleThemeUpdate($hookExtra),
            'core'   => $this->handleCoreUpdate(),
            default  => null,
        };
    }

    /**
     * Rebaseline and mark recently-updated the plugins listed in $hookExtra.
     *
     * @param array<string,mixed> $hookExtra Upgrader metadata.
     */
    private function handlePluginUpdate(array $hookExtra): void
    {
        $plugins = $hookExtra['plugins'] ?? [];
        if (!is_array($plugins)) {
            return;
        }
        // Plugin_Upgrader::upgrade() (including background auto-updates)
        // supplies singular `plugin`; bulk_upgrade() supplies `plugins`.
        if (isset($hookExtra['plugin'])) {
            $plugins[] = $hookExtra['plugin'];
        }

        $pluginsDir = rtrim(str_replace('\\', '/', WP_PLUGIN_DIR), '/') . '/';
        $abspath    = rtrim(str_replace('\\', '/', ABSPATH), '/') . '/';

        $seen = [];
        foreach ($plugins as $pluginBasename) {
            if (!self::validPluginBasename($pluginBasename) || isset($seen[$pluginBasename])) {
                continue;
            }
            $seen[$pluginBasename] = true;

            // `$pluginBasename` is of the form `acme-plugin/acme-plugin.php`
            // for a multi-file plugin, or `acme-plugin.php` for a single-file
            // plugin sitting directly in plugins/. dirname() on the single-
            // file form returns '.' — treat that as "whole plugins dir entry".
            $pluginDirSlug = dirname($pluginBasename);

            if ($pluginDirSlug === '' || $pluginDirSlug === '.') {
                // Single-file plugin — rebaseline only the file itself.
                $absoluteFile = $pluginsDir . $pluginBasename;
                $relative     = $this->toRelative(absolutePath: $absoluteFile, basePath: $abspath);
                $this->fileIntegrity->regeneratePartialChecksums($relative);
                $this->markRecentlyUpdated($relative);

                $this->logService->info(
                    module: self::MODULE,
                    message: 'Auto-rebaselined after update: ' . $relative,
                    context: ['type' => 'plugin', 'path' => $relative],
                );

                continue;
            }

            // Multi-file plugin — rebaseline the whole plugin directory.
            $absoluteDir = $pluginsDir . $pluginDirSlug . '/';
            $relative    = $this->toRelative(absolutePath: $absoluteDir, basePath: $abspath);
            $this->fileIntegrity->regeneratePartialChecksums($relative);
            $this->markRecentlyUpdated($relative);

            $this->logService->info(
                module: self::MODULE,
                message: 'Auto-rebaselined after update: ' . $relative,
                context: ['type' => 'plugin', 'path' => $relative],
            );
        }
    }

    /** @return bool A plugin identity must not escape the plugin directory during partial rebaseline. */
    private static function validPluginBasename(mixed $basename): bool
    {
        if (!is_string($basename) || strlen($basename) > 512
            || preg_match('#^(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.php$#D', $basename) !== 1) {
            return false;
        }
        foreach (explode('/', $basename) as $segment) {
            if ($segment === '.' || $segment === '..') {
                return false;
            }
        }
        return true;
    }

    /**
     * Rebaseline and mark recently-updated the themes listed in $hookExtra.
     *
     * @param array<string,mixed> $hookExtra Upgrader metadata.
     */
    private function handleThemeUpdate(array $hookExtra): void
    {
        $themes = $hookExtra['themes'] ?? [];

        if (!is_array($themes) || $themes === []) {
            return;
        }

        $themesRoot = rtrim(str_replace('\\', '/', get_theme_root()), '/') . '/';
        $abspath    = rtrim(str_replace('\\', '/', ABSPATH), '/') . '/';

        foreach ($themes as $themeStylesheet) {
            if (!is_string($themeStylesheet) || $themeStylesheet === '') {
                continue;
            }

            $absoluteDir = $themesRoot . $themeStylesheet . '/';
            $relative    = $this->toRelative(absolutePath: $absoluteDir, basePath: $abspath);
            $this->fileIntegrity->regeneratePartialChecksums($relative);
            $this->markRecentlyUpdated($relative);

            $this->logService->info(
                module: self::MODULE,
                message: 'Auto-rebaselined after update: ' . $relative,
                context: ['type' => 'theme', 'path' => $relative],
            );
        }
    }

    /**
     * Rebaseline core files covered by the integrity scan.
     *
     * Core updates touch wp-admin/, wp-includes/, and the root PHP files.
     * Three partial-rebaseline calls — one per prefix — cover the whole
     * set without rebuilding the entire checksum map.
     */
    private function handleCoreUpdate(): void
    {
        $corePrefixes = [
            'wp-admin/',
            'wp-includes/',
            // Root PHP files have no common directory prefix; pass the
            // empty string and FileIntegrity's regeneratePartialChecksums
            // will match every entry. Cheap on the small fleet-sized
            // checksum map; the alternative (enumerating ROOT_PHP_FILES
            // here) duplicates knowledge that lives in FileIntegrity.
            '',
        ];

        foreach ($corePrefixes as $prefix) {
            $this->fileIntegrity->regeneratePartialChecksums($prefix);
        }

        // Mark every core prefix as recently updated, including the root
        // bucket. A 7-day grace window on "" effectively whitelists any
        // core file for the week — acceptable: core updates are rare,
        // and legitimate core updates are the exact event we are suppressing
        // alerts for. A malicious post-update edit still reaches the next
        // week's scan after the marker expires.
        foreach (['wp-admin/', 'wp-includes/', ''] as $prefix) {
            $this->markRecentlyUpdated($prefix === '' ? 'wp-core-root' : $prefix);
        }

        $this->logService->info(
            module: self::MODULE,
            message: 'Auto-rebaselined after core update',
            context: ['type' => 'core'],
        );
    }

    /**
     * Plant a "recently updated" marker in the object cache.
     *
     * Key shape: `hmdg_recent_update_<sha256(relative path)>`.
     *
     * @param string $relativePath Relative path (with trailing slash for dirs).
     */
    private function markRecentlyUpdated(string $relativePath): void
    {
        $key = self::RECENT_UPDATE_PREFIX . hash('sha256', $relativePath);

        $this->cacheService->set(
            key: $key,
            value: time(),
            expiration: self::RECENT_UPDATE_TTL,
        );
    }

    /**
     * Convert an absolute path to a relative-to-ABSPATH path with forward
     * slashes.
     */
    private function toRelative(string $absolutePath, string $basePath): string
    {
        $normalised = str_replace('\\', '/', $absolutePath);

        if (str_starts_with($normalised, $basePath)) {
            return ltrim(substr($normalised, strlen($basePath)), '/');
        }

        return $normalised;
    }
}
