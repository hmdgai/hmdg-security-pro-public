<?php

declare(strict_types=1);

/** Exercise the real orchestrator and update callback with isolated service dependencies. */
namespace {
    class MonitorTestDependency { public function __construct(mixed ...$arguments) {} }
    class WP_Upgrader {}
    define('ABSPATH', '/fictional-wordpress/');
    define('WP_PLUGIN_DIR', '/fictional-wordpress/wp-content/plugins');
    define('DAY_IN_SECONDS', 86400);
    define('HMDG_SECURITY_VERSION', '1.11.1');
    $GLOBALS['monitor_context'] = ['admin' => false, 'cron' => false];
    $GLOBALS['monitor_hooks'] = [];
    $GLOBALS['monitor_cache'] = [];
    $GLOBALS['monitor_paths'] = [];
    $GLOBALS['monitor_option_reads'] = 0;
    $GLOBALS['monitor_checks'] = 0;
    $_SERVER['REQUEST_METHOD'] = 'GET';
    function is_admin(): bool { return $GLOBALS['monitor_context']['admin']; }
    function wp_doing_cron(): bool { return $GLOBALS['monitor_context']['cron']; }
    function wp_doing_ajax(): bool { return false; }
    function get_option(string $name, mixed $default = false): mixed
    {
        $GLOBALS['monitor_option_reads']++;
        return \HMDG\Security\Admin\Schema::VERSION;
    }
    function add_filter(string $name, callable $callback, int $priority = 10, int $arguments = 1): void
    {
        $GLOBALS['monitor_hooks'][$name][] = $callback;
    }
    function add_action(string $name, callable $callback, int $priority = 10, int $arguments = 1): void
    {
        add_filter($name, $callback, $priority, $arguments);
    }
    function wp_cache_set(string $key, mixed $value, string $group = '', int $ttl = 0): bool
    {
        $GLOBALS['monitor_cache'][$group . '/' . $key] = ['value' => $value, 'ttl' => $ttl];
        return true;
    }
    function monitorCheck(bool $condition, string $message): void
    {
        $GLOBALS['monitor_checks']++;
        if (!$condition) { throw new \RuntimeException('FAIL: ' . $message); }
    }
}
namespace HMDG\Security { class SecurityConfig extends \MonitorTestDependency {} }
namespace HMDG\Security\Admin {
    class Schema {
        public const VERSION = 'schema-current';
        public const OPTION_VERSION = 'schema-version';
        public static function lockoutLogTableName(): string { return 'fictional_lockout_log'; }
    }
    class FindingsRepository extends \MonitorTestDependency {}
    class LockoutLogRepository extends \MonitorTestDependency {}
    class QuarantineService extends \MonitorTestDependency {}
}
namespace HMDG\Security\Compatibility {
    class HmdgHelpersCompat { public static function get_conflict_report(): array { return []; } }
}
namespace HMDG\Security\Detection {
    class PathClassifier extends \MonitorTestDependency {}
    class UpdateCorrelator extends \MonitorTestDependency {}
    class CoreChecksumClient extends \MonitorTestDependency {}
    class RiskScorer extends \MonitorTestDependency {}
    class AlertDispatcher extends \MonitorTestDependency { public function setQuarantineService(mixed $service): void {} }
}
namespace HMDG\Security\Detection\SignalDetectors {
    class Baseline extends \MonitorTestDependency {}
    class CodeContext extends \MonitorTestDependency {}
    class Obfuscation extends \MonitorTestDependency {}
    class PathAnomaly extends \MonitorTestDependency {}
    class Persistence extends \MonitorTestDependency {}
    class RemoteExec extends \MonitorTestDependency {}
}
namespace HMDG\Security\Services {
    class AlertService extends \MonitorTestDependency {}
    class LogService extends \MonitorTestDependency {
        public function info(string $module, string $message, array $context = []): void {}
    }
    class BuilderDetectionService extends \MonitorTestDependency {
        public function isElementorInstalled(): bool { return false; }
        public function isDiviInstalled(): bool { return false; }
    }
    class CronService extends \MonitorTestDependency {
        public const HOOK_INTEGRITY = 'integrity';
        public const HOOK_SCAN_BATCH = 'integrity-batch';
        public const HOOK_MALWARE = 'malware';
        public const HOOK_MALWARE_BATCH = 'malware-batch';
        public const HOOK_CLEANUP = 'cleanup';
        public function registerCustomIntervals(): void {}
        public function registerScheduledEvents(): void {}
        public function bindReportPlaceholders(): void {}
        public function logEnvironmentOnBoot(): void {}
    }
}
namespace HMDG\Security\Modules {
    class FileIntegrity extends \MonitorTestDependency {
        public function runScan(): void {}
        public function regeneratePartialChecksums(string $prefix): void { $GLOBALS['monitor_paths'][] = $prefix; }
    }
    class MalwareScanner extends \MonitorTestDependency { public function runScan(): void {} }
    class DatabaseCleanup extends \MonitorTestDependency { public function runCleanup(): void {} }
    class Headers extends \MonitorTestDependency {}
    class Hardening extends \MonitorTestDependency {}
}
namespace {
    require_once __DIR__ . '/../includes/Services/ObjectCacheService.php';
    require_once __DIR__ . '/../includes/Services/ReleaseMetadata.php';
    require_once __DIR__ . '/../includes/Services/ReleaseUpdater.php';
    require_once __DIR__ . '/../includes/Modules/UpdateMonitor.php';
    require_once __DIR__ . '/../includes/Plugin.php';

    function bootRealOrchestrator(): void
    {
        $reflection = new \ReflectionClass(\HMDG\Security\Plugin::class);
        $plugin = $reflection->newInstanceWithoutConstructor();
        foreach ($reflection->getProperties() as $property) {
            if (!$property->isInitialized($plugin)) {
                $dependency = new \ReflectionClass($property->getType()->getName());
                $property->setValue($plugin, $dependency->newInstanceWithoutConstructor());
            }
        }
        $plugin->boot();
    }
    function monitorCallbacks(): array
    {
        return array_values(array_filter($GLOBALS['monitor_hooks']['upgrader_process_complete'] ?? [],
            static fn (callable $callback): bool => is_array($callback) && $callback[0] instanceof \HMDG\Security\Modules\UpdateMonitor));
    }

    bootRealOrchestrator();
    monitorCheck(monitorCallbacks() === [], 'actual frontend boot does not instantiate/register the update monitor');
    monitorCheck(!isset($GLOBALS['monitor_hooks']['update_plugins_github.com']), 'actual frontend boot has no release updater');
    monitorCheck($GLOBALS['monitor_option_reads'] === 0 && $GLOBALS['monitor_cache'] === [], 'frontend context adds no update option/cache work');

    $GLOBALS['monitor_hooks'] = [];
    $GLOBALS['monitor_context']['cron'] = true;
    bootRealOrchestrator();
    $callbacks = monitorCallbacks();
    monitorCheck(count($callbacks) === 1, 'actual cron boot registers one update monitor before its early return');
    monitorCheck(isset($GLOBALS['monitor_hooks']['update_plugins_github.com']), 'cron also registers the signed release updater');
    $monitor = $callbacks[0];
    $upgrader = new WP_Upgrader();
    $own = 'hmdg-security-pro/hmdg-security-pro.php';
    $prefix = 'wp-content/plugins/hmdg-security-pro/';
    $monitor($upgrader, ['action' => 'update', 'type' => 'plugin', 'plugin' => $own]);
    monitorCheck($GLOBALS['monitor_paths'] === [$prefix], 'native singular auto-update rebaselines only this plugin');
    $key = 'hmdg_security/' . \HMDG\Security\Modules\UpdateMonitor::RECENT_UPDATE_PREFIX . hash('sha256', $prefix);
    monitorCheck(isset($GLOBALS['monitor_cache'][$key]), 'singular auto-update marks the expected-update window');
    monitorCheck($GLOBALS['monitor_cache'][$key]['ttl'] === 7 * DAY_IN_SECONDS, 'trust marker retains the existing seven-day TTL');
    $GLOBALS['monitor_paths'] = [];
    $monitor($upgrader, ['action' => 'update', 'type' => 'plugin', 'plugins' => [$own, 'fictional-example/example.php']]);
    monitorCheck($GLOBALS['monitor_paths'] === [$prefix, 'wp-content/plugins/fictional-example/'], 'bulk updates preserve exact per-plugin prefixes');
    $GLOBALS['monitor_paths'] = [];
    $monitor($upgrader, ['action' => 'update', 'type' => 'plugin', 'plugins' => [$own], 'plugin' => $own]);
    monitorCheck($GLOBALS['monitor_paths'] === [$prefix], 'combined singular and bulk identity cannot duplicate rebaseline');
    foreach (['../escape.php', 'folder/../../escape.php', '/absolute.php', 'C:/outside.php', 'folder\\outside.php', "plugin\n.php", ['invalid']] as $identity) {
        $GLOBALS['monitor_paths'] = [];
        $monitor($upgrader, ['action' => 'update', 'type' => 'plugin', 'plugin' => $identity]);
        monitorCheck($GLOBALS['monitor_paths'] === [], 'invalid plugin identity cannot widen the baseline prefix');
    }
    $GLOBALS['monitor_context']['cron'] = false;
    $GLOBALS['monitor_paths'] = [];
    $monitor($upgrader, ['action' => 'update', 'type' => 'plugin', 'plugin' => $own]);
    monitorCheck($GLOBALS['monitor_paths'] === [], 'callback remains a no-op if called from the frontend');

    define('WP_CLI', true);
    $GLOBALS['monitor_hooks'] = [];
    bootRealOrchestrator();
    $callbacks = monitorCallbacks();
    monitorCheck(count($callbacks) === 1, 'actual CLI boot registers exactly one monitor before its early return');
    $callbacks[0]($upgrader, ['action' => 'update', 'type' => 'plugin', 'plugin' => $own]);
    monitorCheck($GLOBALS['monitor_paths'] === [$prefix], 'CLI single-plugin updates use the same scoped rebaseline');
    echo 'PASS: ' . $GLOBALS['monitor_checks'] . " update-monitor integration checks\n";
}
