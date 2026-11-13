<?php

declare(strict_types=1);

/**
 * Exercise real email policy, dispatcher and legacy uploads dispatch.
 * Mail, logs, cache and quarantine are in-memory spies: no WordPress boot,
 * network access, database writes or file mutations occur in this test.
 */
namespace {
    define('ABSPATH', '/fictional-wordpress/');
    define('WP_CONTENT_DIR', ABSPATH . 'wp-content');
    define('DAY_IN_SECONDS', 86400);
    define('MINUTE_IN_SECONDS', 60);
    $GLOBALS['email_policy_checks'] = 0;
    $GLOBALS['email_policy_mail'] = [];

    function emailPolicyCheck(bool $condition, string $message): void
    {
        $GLOBALS['email_policy_checks']++;
        if (!$condition) { throw new RuntimeException('FAIL: ' . $message); }
    }
    function wp_mail(string $to, string $subject, string $message, array $headers = []): bool
    {
        $GLOBALS['email_policy_mail'][] = compact('to', 'subject', 'message', 'headers');
        return true;
    }
    function get_site_url(): string { return 'https://fixture.invalid'; }
}

namespace HMDG\Security\Services {
    /** Records detections without opening a log file. */
    final class LogService
    {
        public array $entries = [];
        public function log(string $severity, string $module, string $message, array $context = []): void
        {
            $this->entries[] = compact('severity', 'module', 'message', 'context');
        }
        public function critical(string $module, string $message, array $context = []): void
        {
            $this->log('CRITICAL', $module, $message, $context);
        }
    }

    /** The policy must stop before consulting builder/import suppression. */
    final class BuilderDetectionService
    {
        public function isBuilderImportActive(): bool
        {
            throw new \RuntimeException('Denied event reached downstream builder suppression');
        }
    }

    /** The policy must not consume a rate-limit slot or query the cache. */
    final class ObjectCacheService
    {
        public function __call(string $method, array $arguments): never
        {
            throw new \RuntimeException('Denied event reached object cache: ' . $method);
        }
    }
    final class CronService {}
}

namespace HMDG\Security\Admin {
    use HMDG\Security\Detection\Severity;

    /** Records requested actions without moving, deleting or writing any file. */
    final class QuarantineService
    {
        public array $actions = [];
        public function flag(string $absolutePath, Severity $severity, array $signals, string $source): void
        {
            $this->actions[] = ['action' => 'flag'] + compact('absolutePath', 'severity', 'signals', 'source');
        }
        public function quarantine(string $absolutePath, Severity $severity, array $signals, string $source): void
        {
            $this->actions[] = ['action' => 'quarantine'] + compact('absolutePath', 'severity', 'signals', 'source');
        }
    }
}

namespace {
    require_once __DIR__ . '/../includes/SecurityConfig.php';
    require_once __DIR__ . '/../includes/SecurityEvent.php';
    require_once __DIR__ . '/../includes/Detection/Severity.php';
    require_once __DIR__ . '/../includes/Detection/SignalCategory.php';
    require_once __DIR__ . '/../includes/Detection/Signal.php';
    require_once __DIR__ . '/../includes/Services/AlertService.php';
    require_once __DIR__ . '/../includes/Detection/AlertDispatcher.php';
    require_once __DIR__ . '/../includes/Modules/FileIntegrity.php';

    use HMDG\Security\Admin\QuarantineService;
    use HMDG\Security\Detection\AlertDispatcher;
    use HMDG\Security\Detection\Severity;
    use HMDG\Security\Detection\Signal;
    use HMDG\Security\Detection\SignalCategory;
    use HMDG\Security\Modules\FileIntegrity;
    use HMDG\Security\SecurityConfig;
    use HMDG\Security\SecurityEvent;
    use HMDG\Security\Services\AlertService;
    use HMDG\Security\Services\BuilderDetectionService;
    use HMDG\Security\Services\CronService;
    use HMDG\Security\Services\LogService;
    use HMDG\Security\Services\ObjectCacheService;

    $config = new SecurityConfig();
    $log = new LogService();
    $builder = new BuilderDetectionService();
    $cache = new ObjectCacheService();
    $alerts = new AlertService($config, $log, $builder, $cache);
    $events = SecurityEvent::cases();
    emailPolicyCheck(count($events) === 13, 'new event cases require an explicit email-policy review');

    foreach ($events as $event) {
        emailPolicyCheck(!$event->emitsEmail(), $event->name . ' has no verified-malware producer');
        $alerts->send($event);
        emailPolicyCheck($GLOBALS['email_policy_mail'] === [], $event->name . ' default send is silent');

        foreach (Severity::cases() as $severity) {
            $alerts->send($event, ['source' => 'email-policy-fixture'], $severity);
            emailPolicyCheck($GLOBALS['email_policy_mail'] === [], $event->name . ' explicit ' . $severity->name . ' cannot bypass policy');
            $alerts->send($event, ['severity_enum' => $severity->value]);
            emailPolicyCheck($GLOBALS['email_policy_mail'] === [], $event->name . ' context ' . $severity->name . ' cannot bypass policy');
        }

        // These are untrusted caller claims, not a verification contract.
        $alerts->send($event, [
            'severity_enum' => Severity::HighRisk->value,
            'verified' => true,
            'confirmed_malware' => true,
            'sha256' => str_repeat('a', 64),
            'recommendation' => 'Caller claims confirmed malware',
        ], Severity::HighRisk);
        emailPolicyCheck($GLOBALS['email_policy_mail'] === [], $event->name . ' caller confirmation claims cannot enable mail');
    }
    emailPolicyCheck($log->entries === [], 'suppression does not duplicate caller-owned logs');

    $dispatcher = new AlertDispatcher($alerts, $log);
    $quarantine = new QuarantineService();
    $dispatcher->setQuarantineService($quarantine);
    $signals = [
        new Signal(SignalCategory::Baseline, 25, 'Fixture baseline drift'),
        new Signal(SignalCategory::Obfuscation, 40, 'Fixture heuristic match', ['line' => 7, 'snippet' => '// fixture only']),
    ];
    $source = 'file_integrity_scan';

    // Exercise the real dispatcher at every tier: heuristic findings must
    // remain logged and flagged without automatic file movement.
    foreach (Severity::cases() as $severity) {
        $path = WP_CONTENT_DIR . '/plugins/fixture/' . $severity->name . '.php';
        $beforeLogs = count($log->entries);
        $beforeActions = count($quarantine->actions);
        $dispatcher->handle($severity, $path, $signals, $source);
        emailPolicyCheck(count($log->entries) === $beforeLogs + 1, $severity->name . ' finding is still logged');
        $entry = $log->entries[$beforeLogs];
        emailPolicyCheck($entry['severity'] === $severity->logLevel()
            && $entry['context']['file'] === $path && $entry['context']['signal_count'] === 2,
            $severity->name . ' retains severity and finding details');

        $expectedAction = match ($severity) {
            Severity::HighRisk, Severity::Suspicious, Severity::NeedsReview => 'flag',
            default => null,
        };
        emailPolicyCheck(count($quarantine->actions) === $beforeActions + (int) ($expectedAction !== null),
            $severity->name . ' retains the existing number of quarantine/flag requests');
        if ($expectedAction !== null) {
            emailPolicyCheck($quarantine->actions[$beforeActions] === [
                'action' => $expectedAction, 'absolutePath' => $path,
                'severity' => $severity, 'signals' => $signals, 'source' => $source,
            ], $severity->name . ' retains the exact action and original evidence');
        }
        emailPolicyCheck($GLOBALS['email_policy_mail'] === [], $severity->name . ' dispatcher sends no email');
    }

    // Activation/CLI callers can lack an admin stack; detection still logs.
    $withoutAdmin = new AlertDispatcher($alerts, $log);
    $beforeLogs = count($log->entries);
    $withoutAdmin->handle(Severity::HighRisk, WP_CONTENT_DIR . '/uploads/fixture.php', $signals, 'malware_scanner');
    emailPolicyCheck(count($log->entries) === $beforeLogs + 1, 'HighRisk without admin services still logs');
    emailPolicyCheck($GLOBALS['email_policy_mail'] === [], 'HighRisk without admin services remains silent');

    // Invoke the actual legacy branch, bypassing only directory traversal.
    // A PHP path alone used to be labelled MalwareDetected; it is not proof.
    $integrity = new FileIntegrity($config, $alerts, $log, $builder, $cache, new CronService());
    $legacyDispatch = new ReflectionMethod(FileIntegrity::class, 'dispatchUploadsPhp');
    $legacyPath = WP_CONTENT_DIR . '/uploads/fixture.php';
    $beforeLogs = count($log->entries);
    $legacyDispatch->invoke($integrity, $legacyPath);
    emailPolicyCheck(count($log->entries) === $beforeLogs + 1, 'legacy uploads PHP detection still logs');
    $entry = $log->entries[$beforeLogs];
    emailPolicyCheck($entry['severity'] === 'CRITICAL' && $entry['module'] === 'FileIntegrity'
        && $entry['context']['file'] === $legacyPath, 'legacy detection retains its original log severity and path');
    emailPolicyCheck($GLOBALS['email_policy_mail'] === [], 'legacy MalwareDetected label does not send mail');

    echo 'PASS: ', $GLOBALS['email_policy_checks'], " email-policy integration checks\n";
}
