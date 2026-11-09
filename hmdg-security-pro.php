<?php

declare(strict_types=1);

/**
 * Plugin Name: HMDG Security Pro
 * Plugin URI:  https://hmdg.co.uk
 * Description: Enterprise WordPress security hardening with full Elementor Pro, Divi Builder, and Hello Theme compatibility. Silent operation - no admin UI. Designed to coexist with HMDG Helpers.
 * Version:     1.11.0
 * Update URI:  https://github.com/hmdgai/hmdg-security-pro-public
 * Author:      HMDG
 * Author URI:  https://hmdg.co.uk
 * Requires PHP: 8.2
 * Requires at least: 6.4
 * License:     Proprietary
 * Text Domain: hmdg-security-pro
 *
 * Plugin slug note: the on-disk slug is `hmdg-security-pro` (directory +
 * main file + text domain + data dir). The older slug `hmdg-security` is
 * hard-coded into HMDG Helpers' `handle_migrations()` auto-deactivation
 * list; renaming side-steps that list so both plugins can run together on
 * the 400+ HMDG client sites. The PHP namespace, internal constants, and
 * display branding remain "HMDG Security" - only the WordPress-facing slug
 * changed. See includes/Compatibility/HmdgHelpersCompat.php for the full
 * coexistence strategy.
 */

defined('ABSPATH') || exit;

define('HMDG_SECURITY_VERSION', '1.11.0');
define('HMDG_SECURITY_PATH', plugin_dir_path(__FILE__));
define('HMDG_SECURITY_URL', plugin_dir_url(__FILE__));

// plugin_basename() is safe to call before `plugins_loaded` - it only does
// string work on __FILE__ and WP_PLUGIN_DIR. Resolves to
// 'hmdg-security-pro/hmdg-security-pro.php' and is used as:
//   - the `doing_action('activate_' . ...)` key in HmdgHelpersCompat
//   - the own-plugin protection guard in ConflictCleaner (the module
//     must NEVER delete the plugin running it)
define('HMDG_SECURITY_PRO_BASENAME', plugin_basename(__FILE__));

/**
 * Classmap autoloader for HMDG\Security namespace.
 *
 * Pre-built map of FQCN â†’ file path eliminates the file_exists() check
 * that a generic PSR-4 walker would do on every class load. With OPcache
 * enabled (default on WP Engine and Flywheel), the require itself is
 * essentially free - but file_exists() still hits the realpath cache.
 * Skipping it shaves measurable microseconds off cold-class instantiation.
 */
spl_autoload_register(static function (string $class): void {
    static $classmap = null;

    if ($classmap === null) {
        $base = HMDG_SECURITY_PATH . 'includes/';
        $classmap = [
            'HMDG\\Security\\Plugin' => $base . 'Plugin.php',
            'HMDG\\Security\\SecurityConfig' => $base . 'SecurityConfig.php',
            'HMDG\\Security\\SecurityEvent' => $base . 'SecurityEvent.php',
            'HMDG\\Security\\Compatibility\\HmdgHelpersCompat' => $base . 'Compatibility/HmdgHelpersCompat.php',
            'HMDG\\Security\\Services\\AlertService' => $base . 'Services/AlertService.php',
            'HMDG\\Security\\Services\\BuilderDetectionService' => $base . 'Services/BuilderDetectionService.php',
            'HMDG\\Security\\Services\\CronService' => $base . 'Services/CronService.php',
            'HMDG\\Security\\Services\\LogService' => $base . 'Services/LogService.php',
            'HMDG\\Security\\Services\\ObjectCacheService' => $base . 'Services/ObjectCacheService.php',
            'HMDG\\Security\\Services\\ReleaseUpdater' => $base . 'Services/ReleaseUpdater.php',
            'HMDG\\Security\\Services\\ReleaseMetadata' => $base . 'Services/ReleaseMetadata.php',
            'HMDG\\Security\\Services\\SignedReleasePackage' => $base . 'Services/SignedReleasePackage.php',
            'HMDG\\Security\\Modules\\ConflictCleaner' => $base . 'Modules/ConflictCleaner.php',
            'HMDG\\Security\\Modules\\DatabaseCleanup' => $base . 'Modules/DatabaseCleanup.php',
            'HMDG\\Security\\Modules\\DiviSecurity' => $base . 'Modules/DiviSecurity.php',
            'HMDG\\Security\\Modules\\ElementorSecurity' => $base . 'Modules/ElementorSecurity.php',
            'HMDG\\Security\\Modules\\FileIntegrity' => $base . 'Modules/FileIntegrity.php',
            'HMDG\\Security\\Modules\\Hardening' => $base . 'Modules/Hardening.php',
            'HMDG\\Security\\Modules\\Headers' => $base . 'Modules/Headers.php',
            'HMDG\\Security\\Modules\\LoginProtection' => $base . 'Modules/LoginProtection.php',
            'HMDG\\Security\\Modules\\MalwareScanner' => $base . 'Modules/MalwareScanner.php',
            // SpamProtection removed in 1.3.0 - see CHANGELOG.
            'HMDG\\Security\\Modules\\UpdateMonitor' => $base . 'Modules/UpdateMonitor.php',
            'HMDG\\Security\\Modules\\UserMonitor' => $base . 'Modules/UserMonitor.php',
            // v1.4.0 detection engine.
            'HMDG\\Security\\Detection\\Severity' => $base . 'Detection/Severity.php',
            'HMDG\\Security\\Detection\\SignalCategory' => $base . 'Detection/SignalCategory.php',
            'HMDG\\Security\\Detection\\Signal' => $base . 'Detection/Signal.php',
            'HMDG\\Security\\Detection\\PathClass' => $base . 'Detection/PathClass.php',
            'HMDG\\Security\\Detection\\PathClassifier' => $base . 'Detection/PathClassifier.php',
            'HMDG\\Security\\Detection\\UpdateCorrelator' => $base . 'Detection/UpdateCorrelator.php',
            'HMDG\\Security\\Detection\\CoreChecksumClient' => $base . 'Detection/CoreChecksumClient.php',
            'HMDG\\Security\\Detection\\RiskScorer' => $base . 'Detection/RiskScorer.php',
            'HMDG\\Security\\Detection\\AlertDispatcher' => $base . 'Detection/AlertDispatcher.php',
            'HMDG\\Security\\Detection\\SignalDetectors\\Obfuscation' => $base . 'Detection/SignalDetectors/Obfuscation.php',
            'HMDG\\Security\\Detection\\SignalDetectors\\CodeContext' => $base . 'Detection/SignalDetectors/CodeContext.php',
            'HMDG\\Security\\Detection\\SignalDetectors\\RemoteExec' => $base . 'Detection/SignalDetectors/RemoteExec.php',
            'HMDG\\Security\\Detection\\SignalDetectors\\Persistence' => $base . 'Detection/SignalDetectors/Persistence.php',
            'HMDG\\Security\\Detection\\SignalDetectors\\PathAnomaly' => $base . 'Detection/SignalDetectors/PathAnomaly.php',
            'HMDG\\Security\\Detection\\SignalDetectors\\Baseline' => $base . 'Detection/SignalDetectors/Baseline.php',
            // v1.5.0 operations UI (admin-only - never loads on anonymous front-end).
            'HMDG\\Security\\Admin\\Schema' => $base . 'Admin/Schema.php',
            'HMDG\\Security\\Admin\\FindingsRepository' => $base . 'Admin/FindingsRepository.php',
            'HMDG\\Security\\Admin\\LockoutLogRepository' => $base . 'Admin/LockoutLogRepository.php',
            'HMDG\\Security\\Admin\\QuarantineService' => $base . 'Admin/QuarantineService.php',
            'HMDG\\Security\\Admin\\LockoutsListTable' => $base . 'Admin/LockoutsListTable.php',
            'HMDG\\Security\\Admin\\LockoutHistoryListTable' => $base . 'Admin/LockoutHistoryListTable.php',
            'HMDG\\Security\\Admin\\QuarantineListTable' => $base . 'Admin/QuarantineListTable.php',
            'HMDG\\Security\\Admin\\AdminActions' => $base . 'Admin/AdminActions.php',
            'HMDG\\Security\\Admin\\AdminPage' => $base . 'Admin/AdminPage.php',
        ];
    }

    if (isset($classmap[$class])) {
        require $classmap[$class];
    }
});

/**
 * Activation hook - set up filesystem artefacts and schedule cron events.
 *
 * Uses LOCK_EX on every file write to prevent torn writes if the activation
 * hook fires concurrently (rare but possible on heavily-load-balanced setups).
 */
register_activation_hook(__FILE__, static function (): void {
    // Ensure data directory exists. The data dir slug follows the plugin
    // slug: `wp-content/hmdg-security-pro/`. The PHP namespace/branding
    // ("HMDG Security") is separate from the on-disk slug.
    $data_dir = WP_CONTENT_DIR . '/hmdg-security-pro';
    if (!is_dir($data_dir)) {
        wp_mkdir_p($data_dir);
    }

    // Protect data directory from web access
    $htaccess = $data_dir . '/.htaccess';
    if (!file_exists($htaccess)) {
        file_put_contents($htaccess, "Order deny,allow\nDeny from all\n", LOCK_EX);
    }

    $index = $data_dir . '/index.php';
    if (!file_exists($index)) {
        file_put_contents($index, '<?php // Silence is golden.', LOCK_EX);
    }

    // Block PHP execution in uploads directory
    $uploads_dir = wp_upload_dir()['basedir'];
    $uploads_htaccess = $uploads_dir . '/.htaccess';
    $php_block = "\n# BEGIN HMDG Security\n<Files *.php>\ndeny from all\n</Files>\n# END HMDG Security\n";

    if (file_exists($uploads_htaccess)) {
        $existing = file_get_contents($uploads_htaccess);
        if ($existing !== false && strpos($existing, '# BEGIN HMDG Security') === false) {
            file_put_contents($uploads_htaccess, $existing . $php_block, LOCK_EX);
        }
    } else {
        file_put_contents($uploads_htaccess, $php_block, LOCK_EX);
    }

    // Enforce comment requirements ONCE on activation, not on every request.
    // Previously this was an init hook firing on every page load - DB query
    // on the front-end, which violates the zero-DB-on-front-end rule.
    if (get_option('require_name_email') !== '1') {
        update_option('require_name_email', '1');
    }

    // Install / upgrade the v1.5.0 operations-UI findings table and
    // seed the quarantine directory. dbDelta is idempotent - safe to
    // call on every activation.
    \HMDG\Security\Admin\Schema::install();

    // Cron event scheduling is owned by CronService. We instantiate the
    // services it needs, register custom intervals (so `weekly` is known
    // before wp_schedule_event runs), and let CronService schedule every
    // managed event with timezone-correct UK times + random offset.
    $config          = new \HMDG\Security\SecurityConfig();
    $cache_service   = new \HMDG\Security\Services\ObjectCacheService();
    $builder_service = new \HMDG\Security\Services\BuilderDetectionService();
    $log_service     = new \HMDG\Security\Services\LogService($builder_service);
    $alert_service   = new \HMDG\Security\Services\AlertService(
        config: $config,
        logService: $log_service,
        builderDetection: $builder_service,
        cacheService: $cache_service,
    );
    $cron_service    = new \HMDG\Security\Services\CronService(
        logService: $log_service,
        cacheService: $cache_service,
    );

    // Custom intervals must be registered BEFORE wp_schedule_event so the
    // 'weekly' schedule key resolves on first call.
    $cron_service->registerCustomIntervals();
    apply_filters('cron_schedules', []);
    $cron_service->registerScheduledEvents();

    // Generate initial checksums on activation (uses cron-bypass path:
    // generateChecksums() does not have the wp_doing_cron guard since it
    // is explicitly an activation-time operation).
    $integrity = new \HMDG\Security\Modules\FileIntegrity(
        config: $config,
        alertService: $alert_service,
        logService: $log_service,
        builderDetection: $builder_service,
        cacheService: $cache_service,
        cronService: $cron_service,
    );
    $integrity->generateChecksums();

    // ConflictCleaner runs last, after the plugin's own state is fully
    // initialised. It deactivates and deletes a hard-coded list of
    // conflicting security plugins (MalCare, Wordfence, legacy HMDG
    // Security) and emails the agency operator a summary. It has
    // multiple layers of safety protection against deleting this plugin
    // itself or HMDG Helpers; see includes/Modules/ConflictCleaner.php
    // for the full safety posture.
    //
    // Any throwable inside the cleaner is caught inside run() itself so
    // a cleanup regression can never cause WP to roll back activation.
    $conflict_cleaner = new \HMDG\Security\Modules\ConflictCleaner(
        config: $config,
        logger: $log_service,
    );
    $conflict_cleaner->run();
});

/**
 * Deactivation hook - clean up cron events and .htaccess injections.
 * Log files and checksum files are preserved intentionally.
 */
register_deactivation_hook(__FILE__, static function (): void {
    // Delegate cron + flywheel-notice cleanup to CronService.
    $cache_service   = new \HMDG\Security\Services\ObjectCacheService();
    $builder_service = new \HMDG\Security\Services\BuilderDetectionService();
    $log_service     = new \HMDG\Security\Services\LogService($builder_service);
    $cron_service    = new \HMDG\Security\Services\CronService(
        logService: $log_service,
        cacheService: $cache_service,
    );
    $cron_service->deactivate();

    // Remove .htaccess injection from uploads
    $uploads_dir = wp_upload_dir()['basedir'];
    $uploads_htaccess = $uploads_dir . '/.htaccess';
    if (file_exists($uploads_htaccess)) {
        $content = file_get_contents($uploads_htaccess);
        if ($content !== false) {
            $content = preg_replace(
                '/\n?# BEGIN HMDG Security.*?# END HMDG Security\n?/s',
                '',
                $content
            );
            file_put_contents($uploads_htaccess, $content, LOCK_EX);
        }
    }
});

/**
 * Boot the plugin on `plugins_loaded`.
 *
 * Priority strategy:
 *   - Normal request: priority 1. All security hooks register as early as
 *     possible, before any other plugin can shadow them.
 *   - Plugin-activation request: priority 99. HMDG Helpers' security module
 *     hooks `maybe_run_scan()` on admin_init, and `handle_migrations()`
 *     runs inside its constructor on plugins_loaded (priority 10). Even
 *     though HMDG Helpers no longer targets our slug after the
 *     `hmdg-security-pro` rename, we still let it finish its own
 *     plugins_loaded work first during activation to eliminate any
 *     residual timing surprise.
 *
 * Even at priority 99, every security hook still registers in plugins_loaded
 * - well before `init`, `template_redirect`, admin_menu, or any point where
 * request-handling begins - so there is no protective-gap window.
 */
add_action('plugins_loaded', static function (): void {
    $plugin = new \HMDG\Security\Plugin();
    $plugin->boot();
}, \HMDG\Security\Compatibility\HmdgHelpersCompat::is_activation_request() ? 99 : 1, 0);
