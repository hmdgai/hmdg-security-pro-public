<?php

declare(strict_types=1);

namespace HMDG\Security\Modules;

use HMDG\Security\Compatibility\HmdgHelpersCompat;
use HMDG\Security\Detection\AlertDispatcher;
use HMDG\Security\Detection\RiskScorer;
use HMDG\Security\Detection\Signal;
use HMDG\Security\Detection\SignalDetectors\Baseline;
use HMDG\Security\Detection\SignalDetectors\CodeContext;
use HMDG\Security\Detection\SignalDetectors\Obfuscation;
use HMDG\Security\Detection\SignalDetectors\PathAnomaly;
use HMDG\Security\Detection\SignalDetectors\Persistence;
use HMDG\Security\Detection\SignalDetectors\RemoteExec;
use HMDG\Security\Detection\Severity;
use HMDG\Security\SecurityConfig;
use HMDG\Security\SecurityEvent;
use HMDG\Security\Services\AlertService;
use HMDG\Security\Services\BuilderDetectionService;
use HMDG\Security\Services\CronService;
use HMDG\Security\Services\LogService;
use HMDG\Security\Services\ObjectCacheService;
use HMDG\Security\Services\ProtectedRootPaths;
use HMDG\Security\Services\SafeFileWriter;

/**
 * Monitors WordPress core files, active plugins, and the active theme
 * for unauthorised modifications by comparing SHA-256 checksums against
 * a stored baseline.
 *
 * Checksums are generated on plugin activation and refreshed after every
 * successful scan. The scan runs weekly via WP-Cron, processes files in
 * batches of 200 to prevent timeouts, and schedules follow-up events for
 * remaining work. Additionally scans the uploads directory for PHP files,
 * which are almost always backdoors.
 *
 * Builder-aware: Elementor regenerates CSS in uploads/elementor/css/ on
 * every save, and Divi continuously rebuilds its et-cache directory.
 * Both paths are excluded from integrity checks. Elementor's temporary
 * import directory is exempted during active import operations.
 *
 * Hooks are NOT registered in the constructor - Plugin.php registers
 * cron event callbacks externally via add_action.
 *
 * @since 1.0.0
 */
final class FileIntegrity
{
    /** Module identifier used in log entries. */
    private const MODULE = 'FileIntegrity';

    /** Maximum files to check per cron invocation. */
    private const BATCH_SIZE = 200;

    /** Cache key for tracking scan progress between batches. */
    private const CACHE_KEY_OFFSET = 'integrity_scan_offset';

    /** Seconds until follow-up scan event fires (5 minutes per spec). */
    private const FOLLOW_UP_DELAY = 5 * MINUTE_IN_SECONDS;

    /** Maximum file size for content-detector reads. */
    private const CONTENT_DETECTOR_MAX_FILE_SIZE = 2 * 1024 * 1024;

    /** v1.9.0 — WPE + Flywheel known-good mu-plugin basenames. Match on basename only. */
    private const KNOWN_HOST_MU_PLUGINS = [
        'wpe-common.php',
        'mu-plugin.php',
        'stop-long-comments.php',
        'force-strong-passwords.php',
        'slt-force-strong-passwords.php',
        'flywheel-heartbeat.php',
        'disable-emojis.php',
        'hmdg-fix-upload-permissions.php',
    ];

    /** v1.9.0 — directories whose contents are host-managed and skipped entirely. */
    private const KNOWN_HOST_MU_DIRS = [
        'wpe-common',
    ];

    /** v1.9.0 — hard cap per run to avoid runaway on pathological installs. */
    private const MU_PLUGINS_MAX_FILES_PER_RUN = 500;

    /**
     * Job name used as the lock key suffix and the follow-up event hook.
     *
     * Matches CronService::HOOK_INTEGRITY (without the prefix). The
     * overlap-lock key is `hmdg_<JOB_NAME>_lock` per the agreed pattern.
     */
    private const JOB_NAME = 'weekly_file_integrity_check';

    /**
     * Directory names skipped during recursive PHP file collection.
     *
     * @var list<string>
     */
    private const SKIP_DIRECTORIES = [
        'node_modules',
        '.git',
        '.svn',
        '.hg',
        'et-cache',
        'cache',
        'wflogs',
        '__pycache__',
        'vendor/bin',
    ];

    /**
     * Root PHP files at the WordPress installation root to monitor.
     *
     * @var list<string>
     */
    private const ROOT_PHP_FILES = [
        'wp-activate.php',
        'wp-blog-header.php',
        'wp-comments-post.php',
        'wp-config-sample.php',
        'wp-cron.php',
        'wp-links-opml.php',
        'wp-load.php',
        'wp-login.php',
        'wp-mail.php',
        'wp-settings.php',
        'wp-signup.php',
        'wp-trackback.php',
        'index.php',
        'xmlrpc.php',
    ];
    /**
     * Byte-exact allowlist of known-safe index.php stubs.
     *
     * @var list<string>
     */
    private const BENIGN_STUBS = [
        '<?php',
        '<?php ',
        "<?php\n// Silence is golden",
        "<?php\n// Silence is golden.",
        "<?php\n//Silence is golden",
        "<?php\n//Silence is golden.",
        "<?php\r\n// Silence is golden",
        "<?php\r\n// Silence is golden.",
        "<?php\r\n// Silence is golden\r\n?>",
        "<?php\r\n// Silence is golden.\r\n?>",
        '<?php //Silence is golden',
        '<?php //Silence is golden.',
        '<?php // Silence is golden',
        '<?php // Silence is golden.',
        '<?php /* Silence is golden */',
        '<?php /* Silence is golden. */',
        '<?php /** Silence is golden */',
        '<?php /** Silence is golden. */',
        "<?php\n// There are many ways to WordPress.",
        "<?php\n// There are many ways to WordPress",
        "<?php\nif (!defined('ABSPATH')) {\n\texit;\n}",
        "<?php\nif ( ! defined( 'ABSPATH' ) ) {\n\texit;\n}",
        "<?php\nif (!defined('ABSPATH')) {\n    exit;\n}",
        "<?php\nif ( ! defined( 'ABSPATH' ) ) {\n    exit;\n}",
        "<?php\nif (!defined('ABSPATH')) {\n    die('Access denied.');\n}",
    ];

    /**
     * @param SecurityConfig          $config              Immutable plugin configuration.
     * @param AlertService            $alertService        Alert dispatch service (kept for legacy contexts).
     * @param LogService              $logService          Structured logging service.
     * @param BuilderDetectionService $builderDetection    Page builder detection service.
     * @param ObjectCacheService      $cacheService        Object cache wrapper.
     * @param CronService             $cronService         Cron lock + scheduling.
     * @param RiskScorer|null         $riskScorer          v1.4.0 risk-scoring engine (null for activation-only flows).
     * @param AlertDispatcher|null    $alertDispatcher     v1.4.0 severity-gated dispatcher (null for activation-only flows).
     * @param Baseline|null           $baselineDetector    Baseline signal factory.
     * @param PathAnomaly|null        $pathAnomalyDetector PathAnomaly signal detector.
     * @param Obfuscation|null        $obfuscationDetector Obfuscation signal detector.
     * @param CodeContext|null        $codeContextDetector CodeContext signal detector.
     * @param RemoteExec|null         $remoteExecDetector  RemoteExec signal detector.
     * @param Persistence|null        $persistenceDetector Persistence signal detector.
     */
    public function __construct(
        private readonly SecurityConfig $config,
        private readonly AlertService $alertService,
        private readonly LogService $logService,
        private readonly BuilderDetectionService $builderDetection,
        private readonly ObjectCacheService $cacheService,
        private readonly CronService $cronService,
        private readonly ?RiskScorer $riskScorer = null,
        private readonly ?AlertDispatcher $alertDispatcher = null,
        private readonly ?Baseline $baselineDetector = null,
        private readonly ?PathAnomaly $pathAnomalyDetector = null,
        private readonly ?Obfuscation $obfuscationDetector = null,
        private readonly ?CodeContext $codeContextDetector = null,
        private readonly ?RemoteExec $remoteExecDetector = null,
        private readonly ?Persistence $persistenceDetector = null,
    ) {}

    /**
     * Whether an absolute file path lives inside a plugin/theme/core area
     * that was updated within the last 7 days.
     *
     * Walks the relative path from the deepest directory up to the top so
     * that any ancestor marker (plugin root, theme root, wp-admin/, etc.)
     * planted by UpdateMonitor after an `upgrader_process_complete` match
     * is seen. Uses the object-cache markers set by
     * `UpdateMonitor::markRecentlyUpdated()` (7-day TTL). No DB touched.
     *
     * @param string $relativePath Path relative to ABSPATH, forward slashes.
     *
     * @return bool True if any ancestor path has a fresh update marker.
     */
    public function wasRecentlyUpdated(string $relativePath): bool
    {
        if ($relativePath === '') {
            return false;
        }

        $normalised = ltrim(str_replace('\\', '/', $relativePath), '/');

        // Gather every candidate marker key to check, in order from the
        // deepest ancestor down to the broadest fallback. First hit wins.
        $candidates = $this->buildRecentlyUpdatedCandidates(relativePath: $normalised);

        foreach ($candidates as $candidate) {
            $key = UpdateMonitor::RECENT_UPDATE_PREFIX . hash('sha256', $candidate);

            if ($this->cacheService->exists(key: $key)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Build the list of ancestor markers to check for a given relative path.
     *
     * For `wp-content/plugins/acme/sub/file.php` we check, in order:
     *   - wp-content/plugins/acme/sub/ (if applicable)
     *   - wp-content/plugins/acme/
     *   - wp-content/themes/<slug>/  (not relevant for plugin paths, skipped)
     *   - wp-admin/   (for core)
     *   - wp-includes/
     *   - wp-core-root (sentinel used by UpdateMonitor::handleCoreUpdate())
     *
     * @param string $relativePath Normalised forward-slash relative path.
     *
     * @return list<string>
     */
    private function buildRecentlyUpdatedCandidates(string $relativePath): array
    {
        $candidates = [];

        // Plugin ancestors
        if (str_starts_with($relativePath, 'wp-content/plugins/')) {
            $afterPlugins = substr($relativePath, strlen('wp-content/plugins/'));
            $pluginSlug   = strtok($afterPlugins, '/');

            if (is_string($pluginSlug) && $pluginSlug !== '') {
                $candidates[] = 'wp-content/plugins/' . $pluginSlug . '/';
            }
        }

        // Theme ancestors - resolved against the themes root so that
        // non-standard locations (WP_CONTENT_DIR/themes, or anything
        // get_theme_root() returns) are handled.
        $themesRootRelative = ltrim(
            str_replace(
                str_replace('\\', '/', rtrim(ABSPATH, '/\\')) . '/',
                '',
                str_replace('\\', '/', get_theme_root())
            ),
            '/'
        );

        if ($themesRootRelative !== '' && str_starts_with($relativePath, $themesRootRelative . '/')) {
            $afterThemes = substr($relativePath, strlen($themesRootRelative . '/'));
            $themeSlug   = strtok($afterThemes, '/');

            if (is_string($themeSlug) && $themeSlug !== '') {
                $candidates[] = $themesRootRelative . '/' . $themeSlug . '/';
            }
        }

        // Core buckets
        if (str_starts_with($relativePath, 'wp-admin/')) {
            $candidates[] = 'wp-admin/';
            $candidates[] = 'wp-core-root';
        } elseif (str_starts_with($relativePath, 'wp-includes/')) {
            $candidates[] = 'wp-includes/';
            $candidates[] = 'wp-core-root';
        } elseif (!str_contains($relativePath, '/')) {
            // Root-level PHP file (wp-login.php, wp-settings.php, etc.)
            $candidates[] = 'wp-core-root';
        }

        return $candidates;
    }

    /**
     * Regenerate SHA-256 checksums for only files whose stored relative
     * path starts with `$pathPrefix`.
     *
     * Used by UpdateMonitor after an `upgrader_process_complete` firing:
     * the newly updated plugin/theme/core files are re-hashed in place and
     * merged back into the existing checksum map, leaving every other
     * site's checksums alone. Pass the empty string to force a full
     * rebaseline (useful only from UpdateMonitor's core-update path).
     *
     * Writes atomically via writeChecksumFile(). No DB writes.
     *
     * @param string $pathPrefix Relative path prefix to match, e.g.
     *                           'wp-content/plugins/acme/'. Forward slashes.
     */
    public function regeneratePartialChecksums(string $pathPrefix): void
    {
        $storedData = $this->loadChecksumFile();

        if ($storedData === null) {
            $this->logService->info(
                module: self::MODULE,
                message: 'No baseline found - skipping partial rebaseline',
                context: ['prefix' => $pathPrefix],
            );

            return;
        }

        /** @var array<string, string> $checksums */
        $checksums = $storedData['files'] ?? [];

        if ($checksums === []) {
            return;
        }

        $abspath      = $this->normaliseAbspath();
        $normalPrefix = str_replace('\\', '/', $pathPrefix);
        $rebaselined  = 0;

        foreach ($checksums as $relativePath => $_oldHash) {
            if ($normalPrefix !== '' && !str_starts_with($relativePath, $normalPrefix)) {
                continue;
            }

            $absolutePath = $abspath . $relativePath;

            if (!is_file($absolutePath) || !is_readable($absolutePath)) {
                // File removed by the update (e.g. plugin dropped a file).
                // Drop it from the baseline so the next scan does not alert
                // on its absence.
                unset($checksums[$relativePath]);
                $rebaselined++;
                continue;
            }

            $newHash = hash_file(algo: 'sha256', filename: $absolutePath);

            if ($newHash === false) {
                continue;
            }

            $checksums[$relativePath] = $newHash;
            $rebaselined++;
        }

        // Additionally, walk the newly updated directory on disk to add
        // any brand-new files introduced by the update that were NOT in
        // the previous baseline (e.g. a plugin that shipped a new module).
        // This is only done when a non-empty prefix is provided - on a
        // core update we already cover every path via the prefix sweep.
        if ($normalPrefix !== '') {
            $absolutePrefix = $abspath . $normalPrefix;

            if (is_dir($absolutePrefix)) {
                foreach ($this->getPhpFilesRecursively(directory: $absolutePrefix) as $discovered) {
                    $relative = $this->toRelativePath(absolutePath: $discovered, basePath: $abspath);

                    if (isset($checksums[$relative])) {
                        continue;
                    }

                    $newHash = hash_file(algo: 'sha256', filename: $discovered);

                    if ($newHash === false) {
                        continue;
                    }

                    $checksums[$relative] = $newHash;
                    $rebaselined++;
                }
            } elseif (is_file($absolutePrefix)) {
                // Prefix points at a single file (single-file plugin).
                if (!isset($checksums[$normalPrefix])) {
                    $newHash = hash_file(algo: 'sha256', filename: $absolutePrefix);

                    if ($newHash !== false) {
                        $checksums[$normalPrefix] = $newHash;
                        $rebaselined++;
                    }
                }
            }
        }

        $storedData['files'] = $checksums;
        $storedData['generated'] = (new \DateTimeImmutable(
            datetime: 'now',
            timezone: new \DateTimeZone(timezone: 'Europe/London'),
        ))->format(format: 'Y-m-d H:i:s T');

        $this->writeChecksumFile(data: $storedData);

        $this->logService->info(
            module: self::MODULE,
            message: 'Partial checksum rebaseline completed',
            context: [
                'prefix' => $pathPrefix,
                'files_rebaselined' => $rebaselined,
                'total_files' => count($checksums),
            ],
        );
    }

    /**
     * Update the baseline hash for a single file in place.
     *
     * Used after a benign-mismatch decision (e.g. the file belongs to a
     * recently-updated plugin) so that the new on-disk content becomes the
     * new baseline and the next scan does not re-flag it.
     *
     * @param string $relativePath Path relative to ABSPATH.
     * @param string $newHash      Fresh SHA-256 hash of the file.
     */
    private function updateSingleChecksum(string $relativePath, string $newHash): void
    {
        $storedData = $this->loadChecksumFile();

        if ($storedData === null) {
            return;
        }

        /** @var array<string, string> $checksums */
        $checksums = $storedData['files'] ?? [];
        $checksums[$relativePath] = $newHash;
        $storedData['files'] = $checksums;
        $storedData['generated'] = (new \DateTimeImmutable(
            datetime: 'now',
            timezone: new \DateTimeZone(timezone: 'Europe/London'),
        ))->format(format: 'Y-m-d H:i:s T');

        $this->writeChecksumFile(data: $storedData);
    }

    /**
     * Remove a single file from the stored checksum baseline.
     *
     * Used when the scorer determines a deletion is an expected update
     * change, so the stale baseline entry does not re-alert on the next scan.
     */
    private function removeSingleChecksum(string $relativePath): void
    {
        $storedData = $this->loadChecksumFile();

        if ($storedData === null) {
            return;
        }

        /** @var array<string, string> $checksums */
        $checksums = $storedData['files'] ?? [];

        if (!isset($checksums[$relativePath])) {
            return;
        }

        unset($checksums[$relativePath]);
        $storedData['files'] = $checksums;
        $storedData['generated'] = (new \DateTimeImmutable(
            datetime: 'now',
            timezone: new \DateTimeZone(timezone: 'Europe/London'),
        ))->format(format: 'Y-m-d H:i:s T');

        $this->writeChecksumFile(data: $storedData);
    }

    /**
     * Generate baseline checksums for all monitored files.
     *
     * Called on plugin activation. Builds SHA-256 hashes for every core
     * file, active plugin file, and active theme file, then writes the
     * result as JSON to the configured checksums file path.
     */
    public function generateChecksums(): void
    {
        $this->logService->info(
            module: self::MODULE,
            message: 'Generating baseline checksums',
        );

        $allPaths = [
            ...$this->getCorePaths(),
            ...$this->getPluginPaths(),
            ...$this->getThemePaths(),
        ];

        /** @var array<string, string> $checksums */
        $checksums = [];
        $abspath = $this->normaliseAbspath();

        foreach ($allPaths as $filePath) {
            if (!is_file($filePath) || !is_readable($filePath)) {
                continue;
            }

            $relativePath = $this->toRelativePath(absolutePath: $filePath, basePath: $abspath);
            $hash = hash_file(algo: 'sha256', filename: $filePath);

            if ($hash === false) {
                $this->logService->warning(
                    module: self::MODULE,
                    message: 'Failed to hash file during checksum generation',
                    context: ['file' => $filePath],
                );

                continue;
            }

            $checksums[$relativePath] = $hash;
        }

        $wpVersion = get_bloginfo(show: 'version');
        $timestamp = (new \DateTimeImmutable(
            datetime: 'now',
            timezone: new \DateTimeZone(timezone: 'Europe/London'),
        ))->format(format: 'Y-m-d H:i:s T');

        $data = [
            'files' => $checksums,
            'generated' => $timestamp,
            'wp_version' => $wpVersion,
        ];

        $this->writeChecksumFile(data: $data);

        $this->logService->info(
            module: self::MODULE,
            message: 'Baseline checksums generated',
            context: [
                'total_files' => count($checksums),
                'wp_version' => $wpVersion,
            ],
        );
    }

    /**
     * Run the file integrity scan.
     *
     * Called by WP-Cron weekly. Compares current file hashes against the
     * stored baseline, alerts on mismatches and deletions, scans uploads
     * for PHP files, and processes in batches to prevent timeouts.
     */
    public function runScan(): void
    {
        // Last-line-of-defence guard. Even if a misconfigured hook or future
        // dev mistake calls runScan() outside cron context, the visitor
        // never pays the file-hashing cost. WP-CLI is allowed for manual
        // testing via `wp cron event run`.
        if (!wp_doing_cron() && !(defined('WP_CLI') && WP_CLI)) {
            $this->logService->warning(
                module: self::MODULE,
                message: static::class . '::runScan called outside cron context - aborted',
            );
            return;
        }

        // Single-instance overlap lock via CronService. Acquire returns
        // false if another worker already holds it (skip + log). Release
        // happens in `finally` so the lock self-clears even on exception.
        if (!$this->cronService->acquireLock(self::JOB_NAME)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'File integrity scan already in progress - skipping this invocation',
            );
            return;
        }

        try {
            $this->runScanInner();
            $this->cronService->recordRun(CronService::HOOK_INTEGRITY);
        } finally {
            $this->cronService->releaseLock(self::JOB_NAME);
        }
    }

    /**
     * Inner scan loop - wrapped by runScan() with a single-instance lock.
     */
    private function runScanInner(): void
    {
        // Load stored checksums
        $storedData = $this->loadChecksumFile();

        if ($storedData === null) {
            $this->logService->info(
                module: self::MODULE,
                message: 'No stored checksums found - generating baseline and skipping comparison',
            );

            $this->generateChecksums();

            return;
        }

        /** @var array<string, string> $storedChecksums */
        $storedChecksums = $storedData['files'] ?? [];
        $filePaths = array_keys($storedChecksums);
        $totalFiles = count($filePaths);

        // Retrieve batch offset
        $offset = (int) ($this->cacheService->get(key: self::CACHE_KEY_OFFSET) ?: 0);

        $abspath = $this->normaliseAbspath();
        $mismatchCount = 0;
        $checkedCount = 0;
        $batchEnd = min($offset + self::BATCH_SIZE, $totalFiles);

        for ($i = $offset; $i < $batchEnd; $i++) {
            $relativePath = $filePaths[$i];
            $absolutePath = $abspath . $relativePath;

            // Skip excluded paths
            if ($this->isExcludedPath(filePath: $absolutePath)) {
                $checkedCount++;

                continue;
            }

            // Skip builder cache and generated CSS paths
            if ($this->isBuilderGeneratedPath(relativePath: $relativePath)) {
                $checkedCount++;

                continue;
            }

            $expectedHash = $storedChecksums[$relativePath];

            // Check if file has been deleted
            if (!file_exists($absolutePath)) {
                $mismatchCount++;
                $this->recordFileDeleted(
                    absolutePath: $absolutePath,
                    relativePath: $relativePath,
                    expectedHash: $expectedHash,
                );
                $checkedCount++;

                continue;
            }

            // Compare hashes
            $currentHash = hash_file(algo: 'sha256', filename: $absolutePath);

            if ($currentHash === false) {
                $this->logService->warning(
                    module: self::MODULE,
                    message: 'Failed to hash file during scan',
                    context: ['file' => $absolutePath],
                );
                $checkedCount++;

                continue;
            }

            if ($currentHash !== $expectedHash) {
                $mismatchCount++;
                $this->recordFileModified(
                    absolutePath: $absolutePath,
                    relativePath: $relativePath,
                    expectedHash: $expectedHash,
                    currentHash: $currentHash,
                );
            }

            $checkedCount++;
        }

        // Scan uploads for PHP files (runs once at the start of the scan)
        if ($offset === 0) {
            $this->scanUploadsForPhp();
            $this->scanMuPluginsForPhp();
        }

        // Determine if more batches are needed
        if ($batchEnd < $totalFiles) {
            // More files remain - schedule follow-up
            $this->cacheService->set(
                key: self::CACHE_KEY_OFFSET,
                value: $batchEnd,
                expiration: 3600,
            );

            wp_schedule_single_event(
                timestamp: time() + self::FOLLOW_UP_DELAY,
                hook: CronService::HOOK_SCAN_BATCH,
            );

            $this->logService->info(
                module: self::MODULE,
                message: 'Integrity scan batch completed - follow-up scheduled',
                context: [
                    'checked' => $checkedCount,
                    'mismatches' => $mismatchCount,
                    'offset' => $batchEnd,
                    'remaining' => $totalFiles - $batchEnd,
                ],
            );
        } else {
            // Scan complete - reset offset and regenerate checksums
            $this->cacheService->delete(key: self::CACHE_KEY_OFFSET);
            $this->generateChecksums();

            $this->logService->info(
                module: self::MODULE,
                message: 'Integrity scan completed',
                context: [
                    'total_checked' => $offset + $checkedCount,
                    'total_mismatches' => $mismatchCount,
                ],
            );
        }
    }

    /**
     * Return all core file paths to checksum.
     *
     * Includes wp-admin/, wp-includes/, root PHP files, and wp-config.php
     * (which may reside one directory above ABSPATH).
     *
     * @return list<string> Absolute file paths.
     */
    private function getCorePaths(): array
    {
        $abspath = $this->normaliseAbspath();
        $paths = [];

        // Root PHP files
        foreach (self::ROOT_PHP_FILES as $filename) {
            $fullPath = $abspath . $filename;

            if (is_file($fullPath)) {
                $paths[] = $fullPath;
            }
        }

        // wp-config.php (in ABSPATH or one level up)
        $wpConfigInAbspath = $abspath . 'wp-config.php';
        $wpConfigOneUp = dirname($abspath) . '/wp-config.php';

        if (is_file($wpConfigInAbspath)) {
            $paths[] = $wpConfigInAbspath;
        } elseif (is_file($wpConfigOneUp)) {
            $paths[] = $wpConfigOneUp;
        }

        // wp-admin/ directory - all PHP files recursively
        $wpAdminDir = $abspath . 'wp-admin';

        if (is_dir($wpAdminDir)) {
            $paths = [...$paths, ...$this->getPhpFilesRecursively(directory: $wpAdminDir)];
        }

        // wp-includes/ directory - all PHP files recursively
        $wpIncludesDir = $abspath . 'wp-includes';

        if (is_dir($wpIncludesDir)) {
            $paths = [...$paths, ...$this->getPhpFilesRecursively(directory: $wpIncludesDir)];
        }

        // High-sensitivity platform drop-ins in wp-content root.
        foreach (['advanced-cache.php', 'object-cache.php', 'sunrise.php', 'db.php'] as $dropIn) {
            $dropInPath = $this->normaliseDirectoryPath(path: WP_CONTENT_DIR) . $dropIn;

            if (is_file($dropInPath)) {
                $paths[] = $dropInPath;
            }
        }

        // MU plugins are always-loaded executable code and need the same
        // integrity coverage as normal plugins.
        $muPluginsDir = $this->normaliseDirectoryPath(path: WPMU_PLUGIN_DIR);
        if (is_dir($muPluginsDir)) {
            $paths = [...$paths, ...$this->getPhpFilesRecursively(directory: $muPluginsDir)];
        }

        return $paths;
    }

    /**
     * Return file paths for all active plugins.
     *
     * Iterates through every active plugin's directory and collects all
     * PHP files recursively. Single-file plugins (no subdirectory) are
     * included directly.
     *
     * @return list<string> Absolute file paths.
     */
    private function getPluginPaths(): array
    {
        $paths = [];

        /** @var list<string> $activePlugins */
        $activePlugins = get_option('active_plugins', []);

        if (!is_array($activePlugins)) {
            return $paths;
        }

        $pluginsDir = $this->normaliseDirectoryPath(path: WP_PLUGIN_DIR);

        foreach ($activePlugins as $pluginFile) {
            $pluginDir = dirname($pluginsDir . $pluginFile);

            // Single-file plugin (sits directly in plugins/)
            if ($pluginDir === rtrim($pluginsDir, '/')) {
                $singleFile = $pluginsDir . $pluginFile;

                if (is_file($singleFile)) {
                    $paths[] = $singleFile;
                }

                continue;
            }

            // Multi-file plugin - scan entire directory
            if (is_dir($pluginDir)) {
                $paths = [...$paths, ...$this->getPhpFilesRecursively(directory: $pluginDir)];
            }
        }

        return $paths;
    }

    /**
     * Return file paths for the active theme and its parent theme.
     *
     * Scans the active (child) theme directory and, if a parent theme
     * exists, its directory as well for all PHP files.
     *
     * @return list<string> Absolute file paths.
     */
    private function getThemePaths(): array
    {
        $paths = [];

        // Active (child) theme
        $themeDir = get_stylesheet_directory();

        if (is_dir($themeDir)) {
            $paths = [...$paths, ...$this->getPhpFilesRecursively(directory: $themeDir)];
        }

        // Parent theme (if different from child theme)
        $parentThemeDir = get_template_directory();

        if ($parentThemeDir !== $themeDir && is_dir($parentThemeDir)) {
            $paths = [...$paths, ...$this->getPhpFilesRecursively(directory: $parentThemeDir)];
        }

        return $paths;
    }

    /**
     * Check whether a file path falls within any configured exclusion directory.
     *
     * Consults three sources in order:
     *   1. SecurityConfig::$integrityExcludedPaths - static config.
     *   2. HmdgHelpersCompat::get_excluded_paths() - the HMDG Helpers
     *      plugin folder, excluded at runtime when HMDG Helpers is active
     *      on this site. HMDG Helpers updates independently through its
     *      own release channel, so any file hash change there is a
     *      legitimate update, not tampering - flagging it would produce
     *      noise alerts on every HMDG Helpers version bump.
     *
     * @param string $filePath Absolute path to check.
     *
     * @return bool True if the file should be skipped.
     */
    private function isExcludedPath(string $filePath): bool
    {
        $normalisedPath = $this->normalisePath(path: $filePath);

        foreach ($this->config->integrityExcludedPaths as $excludedPath) {
            $normalisedExclusion = $this->normalisePath(path: $excludedPath);

            if (str_starts_with($normalisedPath, $normalisedExclusion)) {
                return true;
            }
        }

        // Runtime exclusions contributed by the HMDG Helpers compatibility
        // layer. The compat class already static-caches its is_active()
        // decision, so repeated calls during a batch are branch-free.
        foreach (HmdgHelpersCompat::get_excluded_paths() as $excludedPath) {
            $normalisedExclusion = $this->normalisePath(path: $excludedPath);

            if (str_starts_with($normalisedPath, $normalisedExclusion)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check whether a relative path belongs to a builder-generated location.
     *
     * These paths change constantly during normal builder operations and
     * must never trigger integrity alerts.
     *
     * @param string $relativePath Path relative to ABSPATH.
     *
     * @return bool True if the file is a builder-generated asset.
     */
    private function isBuilderGeneratedPath(string $relativePath): bool
    {
        $normalisedPath = str_replace('\\', '/', $relativePath);

        // Elementor regenerates CSS in uploads/elementor/css/ on every save
        if (str_contains($normalisedPath, 'wp-content/uploads/elementor/css/')
            && str_ends_with($normalisedPath, '.css')) {
            return true;
        }

        // Divi cache - regenerated constantly
        if (str_contains($normalisedPath, 'wp-content/uploads/et-cache/')) {
            return true;
        }

        // General cache directories
        if (str_contains($normalisedPath, 'wp-content/cache/')) {
            return true;
        }

        // Wordfence logs
        if (str_contains($normalisedPath, 'wp-content/wflogs/')) {
            return true;
        }

        return false;
    }

    /**
     * Recursively scan wp-content/uploads/ for PHP files.
     *
     * PHP files in the uploads directory are almost always backdoors or
     * webshells injected through file-upload vulnerabilities. Each
     * discovery triggers an immediate MalwareDetected alert.
     *
     * Exception: Elementor's temporary import directory is exempted when
     * a builder import operation is actively in progress.
     */
    private function scanUploadsForPhp(): void
    {
        $uploadsDir = WP_CONTENT_DIR . '/uploads';

        if (!is_dir($uploadsDir)) {
            return;
        }

        $phpFiles = $this->getPhpFilesRecursively(directory: $uploadsDir);
        $importActive = $this->builderDetection->isBuilderImportActive();
        $detectionCount = 0;

        foreach ($phpFiles as $phpFile) {
            $normalisedPath = str_replace('\\', '/', $phpFile);

            // Exempt Elementor's temporary import directory during active imports
            if ($importActive && str_contains($normalisedPath, 'wp-content/uploads/elementor/tmp/')) {
                $this->logService->info(
                    module: self::MODULE,
                    message: 'Skipping Elementor temp file during active import',
                    context: ['file' => $phpFile],
                );

                continue;
            }

            // Exempt the canonical WordPress "Silence is golden" index.php
            // stub. WordPress core, many plugins (Yoast, WooCommerce,
            // WPForms), and this plugin's own activation hook drop these
            // files into uploads subdirectories as a directory-listing
            // defence. They are tiny, byte-exact, well-known, and were the
            // dominant source of the uploads-scan false positives across
            // the 276-site fleet.
            if ($this->isBenignIndexStub(path: $phpFile)) {
                $this->logService->info(
                    module: self::MODULE,
                    message: 'Skipping benign Silence-is-golden index.php stub',
                    context: ['file' => $phpFile],
                );

                continue;
            }

            $relativeForRecent = $this->toRelativePath(
                absolutePath: $phpFile,
                basePath: $this->normaliseAbspath(),
            );

            // If the uploads subdirectory belongs to a plugin/theme that
            // was just updated (rare but possible - some plugins drop
            // assets into uploads/<slug>/ during activation/upgrade), skip.
            if ($this->wasRecentlyUpdated(relativePath: $relativeForRecent)) {
                $this->logService->info(
                    module: self::MODULE,
                    message: 'Skipping uploads PHP - area was recently updated',
                    context: ['file' => $phpFile],
                );

                continue;
            }

            $detectionCount++;
            $this->dispatchUploadsPhp(filePath: $phpFile);
        }

        if ($detectionCount > 0) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Uploads PHP scan completed with detections',
                context: ['php_files_found' => $detectionCount],
            );
        }
    }

    /**
     * Send an uploads-directory PHP file through the detection engine.
     *
     * When the detection engine is wired up, collects Persistence
     * Signals via the injected detector and classifies via RiskScorer.
     * Otherwise falls back to a direct MalwareDetected alert for
     * backwards compatibility.
     */
    private function dispatchUploadsPhp(string $filePath): void
    {
        if ($this->persistenceDetector === null
            || $this->riskScorer === null
            || $this->alertDispatcher === null
        ) {
            $this->legacyAlertUploadsPhp(filePath: $filePath);
            return;
        }

        // Read contents for the hidden-iframe signal side-channel. If
        // we cannot read, supply empty string - the uploads-PHP
        // persistence check is path-driven and will still fire.
        $contents = file_get_contents(filename: $filePath);

        if ($contents === false) {
            $contents = '';
        }

        $signals = $this->persistenceDetector->detect(
            absolutePath: $filePath,
            contents: $contents,
        );

        if ($signals === []) {
            // isBenignIndexStub filtered it out - logged upstream.
            return;
        }

        $severity = $this->riskScorer->classify(
            absolutePath: $filePath,
            signals: $signals,
            currentHash: hash_file('md5', $filePath) ?: '',
        );

        $this->alertDispatcher->handle(
            severity: $severity,
            absolutePath: $filePath,
            signals: $signals,
            source: 'file_integrity_uploads_scan',
        );
    }

    /**
     * Recursively scan wp-content/mu-plugins/ for PHP files.
     *
     * mu-plugins auto-load and do not appear in the Plugins admin list,
     * making them a common persistence drop-point. Files are routed
     * through the v1.4+ detector cascade, with a code-owned allowlist
     * for known WP Engine / Flywheel host-managed mu-plugins.
     */
    private function scanMuPluginsForPhp(): void
    {
        if (!wp_doing_cron() && !(defined('WP_CLI') && WP_CLI)) {
            return;
        }

        if (!defined('WPMU_PLUGIN_DIR') || !is_dir(WPMU_PLUGIN_DIR)) {
            return;
        }

        $phpFiles = $this->getPhpFilesRecursively(directory: WPMU_PLUGIN_DIR);
        $fileCount = count($phpFiles);

        if ($fileCount > self::MU_PLUGINS_MAX_FILES_PER_RUN) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'mu-plugins PHP scan hit per-run cap',
                context: ['file_count' => $fileCount, 'cap' => self::MU_PLUGINS_MAX_FILES_PER_RUN],
            );

            $phpFiles = array_slice($phpFiles, 0, self::MU_PLUGINS_MAX_FILES_PER_RUN);
        }

        $detectionCount = 0;

        foreach ($phpFiles as $phpFile) {
            if (in_array(basename($phpFile), self::KNOWN_HOST_MU_PLUGINS, true)) {
                continue;
            }

            if (in_array(basename(dirname($phpFile)), self::KNOWN_HOST_MU_DIRS, true)) {
                continue;
            }

            if ($this->isBenignIndexStub(path: $phpFile)) {
                $this->logService->info(
                    module: self::MODULE,
                    message: 'Skipping benign mu-plugin Silence-is-golden stub',
                    context: ['file' => $phpFile],
                );

                continue;
            }

            if ($this->isTrivialCommentOnlyPhpFile(path: $phpFile)) {
                $this->logService->info(
                    module: self::MODULE,
                    message: 'Skipping trivial comment-only mu-plugin stub',
                    context: ['file' => $phpFile],
                );

                continue;
            }

            $relativeForRecent = $this->toRelativePath(
                absolutePath: $phpFile,
                basePath: $this->normaliseAbspath(),
            );

            if ($this->wasRecentlyUpdated(relativePath: $relativeForRecent)) {
                $this->logService->info(
                    module: self::MODULE,
                    message: 'Skipping mu-plugin PHP - area was recently updated',
                    context: ['file' => $phpFile],
                );

                continue;
            }

            $detectionCount++;
            $this->dispatchMuPluginsPhp(filePath: $phpFile);
        }

        if ($detectionCount > 0) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'mu-plugins PHP scan completed with detections',
                context: ['php_files_found' => $detectionCount],
            );
        }
    }

    /**
     * Send a mu-plugins PHP file through the v1.4+ detection engine.
     *
     * mu-plugins are executable PHP, so the primary decision stays with
     * the full signal-detector cascade rather than a token-only gate.
     */
    private function dispatchMuPluginsPhp(string $filePath): void
    {
        if ($this->baselineDetector === null
            || $this->pathAnomalyDetector === null
            || $this->riskScorer === null
            || $this->alertDispatcher === null
        ) {
            $this->legacyAlertUploadsPhp(filePath: $filePath);
            return;
        }

        $relativePath = $this->toRelativePath(
            absolutePath: $filePath,
            basePath: $this->normaliseAbspath(),
        );

        $sha256 = hash_file('sha256', $filePath);
        if ($sha256 === false) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Failed to hash mu-plugin during scan',
                context: ['file' => $filePath],
            );
            return;
        }

        $newFileSignal = $this->baselineDetector->forNewFile(relativePath: $relativePath);

        /** @var list<Signal> $signals */
        $signals = [
            new Signal(
                category: $newFileSignal->category,
                weight: $newFileSignal->weight,
                label: $newFileSignal->label,
                context: array_merge(
                    $newFileSignal->context,
                    ['sha256' => $sha256],
                ),
            ),
            ...$this->pathAnomalyDetector->detect(
                absolutePath: $filePath,
                baselineMismatch: false,
            ),
            ...$this->runContentDetectors(absolutePath: $filePath),
        ];

        $severity = $this->riskScorer->classify(
            absolutePath: $filePath,
            signals: $signals,
            currentHash: hash_file('md5', $filePath) ?: '',
        );

        $this->alertDispatcher->handle(
            severity: $severity,
            absolutePath: $filePath,
            signals: $signals,
            source: 'mu-plugins',
        );
    }

    /**
     * Legacy alert path for uploads-PHP, used when the detection
     * engine is not wired up.
     */
    private function legacyAlertUploadsPhp(string $filePath): void
    {
        $timestamp = (new \DateTimeImmutable(
            datetime: 'now',
            timezone: new \DateTimeZone(timezone: 'Europe/London'),
        ))->format(format: 'Y-m-d H:i:s T');

        $this->alertService->send(
            event: SecurityEvent::MalwareDetected,
            context: [
                'source'         => 'file_integrity_uploads_scan',
                'file_path'      => $filePath,
                'timestamp'      => $timestamp,
                'site_url'       => get_site_url(),
                'reason'         => 'PHP file found in uploads directory',
                'recommendation' => 'Remove file immediately. PHP files in the uploads directory are almost always backdoors or webshells. '
                    . 'Quarantine the file for forensic analysis before deletion.',
                'unique_key'     => 'uploads_php:' . $filePath,
            ],
        );

        $this->logService->critical(
            module: self::MODULE,
            message: 'PHP file detected in uploads directory (legacy path)',
            context: ['file' => $filePath],
        );
    }

    /**
     * Whether a discovered PHP file is a legitimate benign index.php stub.
     *
     * @param string $path Absolute path to the PHP file.
     *
     * @return bool True if the file is a benign index.php stub.
     */
    private function isBenignIndexStub(string $path): bool
    {
        if (basename($path) !== 'index.php') {
            return false;
        }

        if (!is_file($path) || !is_readable($path)) {
            return false;
        }

        $size = filesize($path);

        if ($size === false || $size < 0) {
            return false;
        }

        if ($size === 0) {
            return true;
        }

        if ($size > 256) {
            return false;
        }

        $contents = file_get_contents($path);

        if ($contents === false) {
            return false;
        }

        $normalised = rtrim($contents);

        if (in_array($normalised, self::BENIGN_STUBS, true)) {
            return true;
        }

        return $this->isCommentOnlyPhpFile($contents);
    }

    /**
     * Fast-path for tiny mu-plugin silencer stubs that contain only an
     * opening PHP tag plus comments/whitespace.
     */
    private function isTrivialCommentOnlyPhpFile(string $path): bool
    {
        if (!is_file($path) || !is_readable($path)) {
            return false;
        }

        $size = filesize($path);

        if ($size === false || $size < 0 || $size > 256) {
            return false;
        }

        $contents = file_get_contents($path);

        if ($contents === false) {
            return false;
        }

        return $this->isCommentOnlyPhpFile($contents);
    }

    /**
     * True if the file contains only a PHP open tag plus comments and whitespace.
     *
     * @security Token-based. Removes PHP comments, then rejects any content
     * containing executable syntax tokens such as $, (, [, ;, backticks, or
     * nested PHP tags.
     */
    private function isCommentOnlyPhpFile(string $contents): bool
    {
        if ($contents === '') {
            return true;
        }

        if (str_starts_with($contents, "\xEF\xBB\xBF")) {
            $contents = substr($contents, 3);
        }

        $contents = ltrim($contents);

        if (!str_starts_with($contents, '<?')) {
            return false;
        }

        $body = preg_replace('/^<\?(?:php)?\s*/', '', $contents) ?? '';
        $body = preg_replace('/\?>\s*$/', '', $body) ?? '';
        $body = preg_replace('#/\*.*?\*/#s', '', $body) ?? '';
        $body = preg_replace('#//[^\r\n]*#', '', $body) ?? '';
        $body = preg_replace('#^\s*\#[^\r\n]*#m', '', $body) ?? '';
        $body = trim($body);

        if ($body === '') {
            return true;
        }

        foreach (['$', '(', '[', ';', '`', '<?', '?>'] as $token) {
            if (str_contains($body, $token)) {
                return false;
            }
        }

        return false;
    }

    /**
     * Record a baseline mismatch as a Signal and route through the
     * v1.4.0 detection engine.
     *
     * When the detection-engine services were not injected (activation
     * path, CLI invocation without full boot), falls back to logging a
     * warning - alerts are not emitted without the scorer + dispatcher.
     *
     * @param string $absolutePath Absolute path to the modified file.
     * @param string $relativePath Path relative to ABSPATH.
     * @param string $expectedHash The stored SHA-256 hash.
     * @param string $currentHash  The current SHA-256 hash.
     */
    private function recordFileModified(
        string $absolutePath,
        string $relativePath,
        string $expectedHash,
        string $currentHash,
    ): void {

        // If the detection engine is not wired up, fall back to the
        // legacy alert path. This preserves correctness for code paths
        // (activation-time checksum generation) that instantiate the
        // module without the optional detection services.
        if ($this->baselineDetector === null
            || $this->pathAnomalyDetector === null
            || $this->riskScorer === null
            || $this->alertDispatcher === null
        ) {
            $this->legacyAlertFileModified(
                absolutePath: $absolutePath,
                relativePath: $relativePath,
                expectedHash: $expectedHash,
                currentHash: $currentHash,
            );
            return;
        }

        /** @var list<Signal> $signals */
        $signals = [
            $this->baselineDetector->forHashMismatch(
                relativePath: $relativePath,
                expectedHash: $expectedHash,
                currentHash: $currentHash,
            ),
            ...$this->pathAnomalyDetector->detect(
                absolutePath: $absolutePath,
                baselineMismatch: true,
            ),
            ...$this->runContentDetectors(absolutePath: $absolutePath),
        ];

        $severity = $this->riskScorer->classify(
            absolutePath: $absolutePath,
            signals: $signals,
            // Core baseline check wants MD5; compute on demand. If we
            // cannot hash, pass empty - fail-closes on core check.
            currentHash: hash_file('md5', $absolutePath) ?: '',
        );

        if ($severity === Severity::ExpectedUpdate) {
            $this->updateSingleChecksum(
                relativePath: $relativePath,
                newHash: $currentHash,
            );
            $this->logService->info(
                module: self::MODULE,
                message: 'Rebaselined after verified-clean file in trusted update window',
                context: ['file' => $absolutePath],
            );
            return;
        }

        $this->alertDispatcher->handle(
            severity: $severity,
            absolutePath: $absolutePath,
            signals: $signals,
            source: 'file_integrity_scan',
        );
    }

    /**
     * Run content-based detectors (Obfuscation, CodeContext, RemoteExec)
     * against the file. Bounded by a fixed size ceiling to avoid OOM on
     * huge files. Returns empty array when detectors aren't wired up.
     *
     * @return list<Signal>
     */
    private function runContentDetectors(string $absolutePath): array
    {
        if ($this->obfuscationDetector === null
            || $this->codeContextDetector === null
            || $this->remoteExecDetector === null
            || $this->persistenceDetector === null
        ) {
            return [];
        }

        $size = @filesize($absolutePath);
        if ($size === false || $size > self::CONTENT_DETECTOR_MAX_FILE_SIZE) {
            return [];
        }

        $contents = @file_get_contents($absolutePath);
        if ($contents === false) {
            return [];
        }

        return array_merge(
            $this->obfuscationDetector->detect(contents: $contents),
            $this->codeContextDetector->detect(contents: $contents),
            $this->remoteExecDetector->detect(contents: $contents),
            $this->persistenceDetector->detect(
                absolutePath: $absolutePath,
                contents: $contents,
            ),
        );
    }

    /**
     * Legacy alert path for baseline mismatches, used when the
     * detection engine is not wired up (activation flow, partial CLI).
     */
    private function legacyAlertFileModified(
        string $absolutePath,
        string $relativePath,
        string $expectedHash,
        string $currentHash,
    ): void {
        $timestamp = (new \DateTimeImmutable(
            datetime: 'now',
            timezone: new \DateTimeZone(timezone: 'Europe/London'),
        ))->format(format: 'Y-m-d H:i:s T');

        $this->alertService->send(
            event: SecurityEvent::FileModified,
            context: [
                'source'            => 'file_integrity_scan',
                'file_path'         => $absolutePath,
                'relative_path'     => $relativePath,
                'original_checksum' => $expectedHash,
                'current_checksum'  => $currentHash,
                'timestamp'         => $timestamp,
                'site_url'          => get_site_url(),
                'recommendation'    => 'Review file for unauthorised changes. Compare against WordPress core checksums at '
                    . 'https://api.wordpress.org/core/checksums/ to determine whether this is a legitimate update or tampering.',
                'unique_key'        => 'file_modified:' . $relativePath,
            ],
        );

        $this->logService->warning(
            module: self::MODULE,
            message: 'File integrity mismatch detected (legacy path)',
            context: [
                'file'     => $absolutePath,
                'expected' => $expectedHash,
                'actual'   => $currentHash,
            ],
        );
    }

    /**
     * Record a baseline deletion as a Signal and route through the
     * v1.4.0 detection engine.
     *
     * @param string $absolutePath Absolute path where the file was expected.
     * @param string $relativePath Path relative to ABSPATH.
     * @param string $expectedHash The stored SHA-256 hash of the deleted file.
     */
    private function recordFileDeleted(
        string $absolutePath,
        string $relativePath,
        string $expectedHash,
    ): void {
        if ($this->baselineDetector === null
            || $this->riskScorer === null
            || $this->alertDispatcher === null
        ) {
            $this->legacyAlertFileDeleted(
                absolutePath: $absolutePath,
                relativePath: $relativePath,
                expectedHash: $expectedHash,
            );
            return;
        }

        /** @var list<Signal> $signals */
        $signals = [
            $this->baselineDetector->forRemovedFile(
                relativePath: $relativePath,
                expectedHash: $expectedHash,
            ),
        ];

        $severity = $this->riskScorer->classify(
            absolutePath: $absolutePath,
            signals: $signals,
            // File is gone - no hash. Empty string means the core
            // baseline check fail-closes (returns false). Expected.
            currentHash: '',
        );

        if ($severity === Severity::ExpectedUpdate) {
            $this->removeSingleChecksum(relativePath: $relativePath);
            $this->logService->info(
                module: self::MODULE,
                message: 'Removed stale baseline entry after expected update deletion',
                context: ['file' => $absolutePath],
            );
            return;
        }

        $this->alertDispatcher->handle(
            severity: $severity,
            absolutePath: $absolutePath,
            signals: $signals,
            source: 'file_integrity_scan',
        );
    }

    /**
     * Legacy alert path for deletions, used when the detection engine
     * is not wired up.
     */
    private function legacyAlertFileDeleted(
        string $absolutePath,
        string $relativePath,
        string $expectedHash,
    ): void {
        $timestamp = (new \DateTimeImmutable(
            datetime: 'now',
            timezone: new \DateTimeZone(timezone: 'Europe/London'),
        ))->format(format: 'Y-m-d H:i:s T');

        $this->alertService->send(
            event: SecurityEvent::FileModified,
            context: [
                'source'            => 'file_integrity_scan',
                'file_path'         => $absolutePath,
                'relative_path'     => $relativePath,
                'original_checksum' => $expectedHash,
                'current_checksum'  => 'FILE_DELETED',
                'timestamp'         => $timestamp,
                'site_url'          => get_site_url(),
                'recommendation'    => 'A monitored file has been deleted. If this was not an intentional update or plugin removal, '
                    . 'investigate immediately - file deletion can indicate an attacker covering their tracks.',
                'unique_key'        => 'file_deleted:' . $relativePath,
            ],
        );

        $this->logService->warning(
            module: self::MODULE,
            message: 'Monitored file has been deleted (legacy path)',
            context: [
                'file'          => $absolutePath,
                'expected_hash' => $expectedHash,
            ],
        );
    }

    /**
     * Recursively collect all PHP files within a directory.
     *
     * Uses RecursiveDirectoryIterator with SKIP_DOTS to traverse the
     * directory tree. Symlinks are followed (default behaviour) to catch
     * symlinked plugin/theme files.
     *
     * @param string $directory Absolute path to the directory to scan.
     *
     * @return list<string> Absolute paths to all PHP files found.
     */
    private function getPhpFilesRecursively(string $directory): array
    {
        $paths = [];

        // Resolve allowed roots once for symlink-escape protection.
        $allowedRoots = array_filter([
            realpath(ABSPATH),
            realpath(WP_CONTENT_DIR),
            realpath(WP_PLUGIN_DIR),
        ]);

        try {
            $iterator = new \RecursiveIteratorIterator(
                iterator: new \RecursiveDirectoryIterator(
                    directory: $directory,
                    flags: \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::UNIX_PATHS,
                ),
                mode: \RecursiveIteratorIterator::LEAVES_ONLY,
            );

            /** @var \SplFileInfo $file */
            foreach ($iterator as $file) {
                if (!$file->isFile() || strtolower($file->getExtension()) !== 'php') {
                    continue;
                }

                $pathname = $file->getPathname();

                // Skip well-known noise directories
                if ($this->isPathInSkipDirectory($pathname)) {
                    continue;
                }

                // Symlink-escape protection: resolve the real path and verify
                // it stays inside one of the allowed roots. Without this, an
                // attacker who can create a symlink in plugins/themes could
                // make the scanner traverse arbitrary filesystem paths.
                $real = realpath($pathname);
                if ($real === false) {
                    continue;
                }
                $realNormalised = str_replace('\\', '/', $real);
                $isAllowed = false;
                foreach ($allowedRoots as $root) {
                    $rootNormalised = str_replace('\\', '/', $root);
                    if (str_starts_with($realNormalised, $rootNormalised)) {
                        $isAllowed = true;
                        break;
                    }
                }
                if (!$isAllowed) {
                    continue;
                }

                $paths[] = $pathname;
            }
        } catch (\UnexpectedValueException $e) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Failed to iterate directory',
                context: [
                    'directory' => $directory,
                    'error' => $e->getMessage(),
                ],
            );
        }

        return $paths;
    }

    /**
     * Whether a file path lies inside any of the SKIP_DIRECTORIES.
     */
    private function isPathInSkipDirectory(string $path): bool
    {
        $normalised = str_replace('\\', '/', $path);

        foreach (self::SKIP_DIRECTORIES as $skip) {
            if (str_contains($normalised, '/' . $skip . '/')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Load the stored checksums JSON file.
     *
     * @return array<string, mixed>|null Decoded checksum data, or null if the file does not exist or is invalid.
     */
    private function loadChecksumFile(): ?array
    {
        $filePath = $this->config->checksumFilePath;

        if (!is_file($filePath) || !is_readable($filePath)) {
            return null;
        }

        $contents = file_get_contents(filename: $filePath);

        if ($contents === false) {
            return null;
        }

        $data = json_decode(json: $contents, associative: true);

        if (!is_array($data)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Checksums file contains invalid JSON',
                context: ['file' => $filePath],
            );

            return null;
        }

        return $data;
    }

    /**
     * Write checksum data to the configured JSON file.
     *
     * Creates the parent directory if needed, then replaces the complete JSON
     * atomically without waiting for a filesystem lock.
     *
     * @param array<string, mixed> $data Checksum data to serialise.
     */
    private function writeChecksumFile(array $data): void
    {
        $filePath = $this->config->checksumFilePath;
        $directory = dirname($filePath);

        if (!ProtectedRootPaths::allowsWrite($filePath) || !ProtectedRootPaths::allowsWrite($directory)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Checksum write refused for protected WordPress root/core destination',
            );
            return;
        }

        if (!is_dir($directory)) {
            wp_mkdir_p(target: $directory);
        }

        $json = json_encode(
            value: $data,
            flags: JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        );

        if ($json === false) {
            $this->logService->critical(
                module: self::MODULE,
                message: 'Failed to encode checksums as JSON',
            );

            return;
        }

        $written = SafeFileWriter::replace($filePath, $json);

        if ($written === false) {
            $this->logService->critical(
                module: self::MODULE,
                message: 'Failed to write checksums file',
                context: ['file' => $filePath],
            );
        }
    }

    /**
     * Convert an absolute path to a path relative to the given base.
     *
     * @param string $absolutePath The absolute file path.
     * @param string $basePath     The base directory to strip.
     *
     * @return string Relative path with forward slashes.
     */
    private function toRelativePath(string $absolutePath, string $basePath): string
    {
        $normalisedAbsolute = $this->normalisePath(path: $absolutePath);
        $normalisedBase = $this->normalisePath(path: $basePath);

        if (str_starts_with($normalisedAbsolute, $normalisedBase)) {
            return ltrim(substr($normalisedAbsolute, strlen($normalisedBase)), '/');
        }

        // File outside ABSPATH (e.g. wp-config.php one level up)
        return $normalisedAbsolute;
    }

    /**
     * Normalise a file path to use forward slashes.
     *
     * @param string $path The path to normalise.
     *
     * @return string Path with all backslashes converted to forward slashes.
     */
    private function normalisePath(string $path): string
    {
        return str_replace('\\', '/', $path);
    }

    /**
     * Return ABSPATH with a trailing forward slash and normalised separators.
     *
     * @return string Normalised ABSPATH.
     */
    private function normaliseAbspath(): string
    {
        return rtrim($this->normalisePath(path: ABSPATH), '/') . '/';
    }

    /**
     * Ensure a directory path ends with a trailing forward slash.
     *
     * @param string $path The directory path to normalise.
     *
     * @return string Path with trailing forward slash.
     */
    private function normaliseDirectoryPath(string $path): string
    {
        return rtrim($this->normalisePath(path: $path), '/') . '/';
    }
}
