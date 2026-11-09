<?php

declare(strict_types=1);

/** Real filesystem writes are confined to a uniquely owned temporary fixture. */
namespace {
    $fixture = sys_get_temp_dir() . '/hmdg-root-writes-' . bin2hex(random_bytes(8));
    if (!mkdir($fixture, 0700)) { throw new RuntimeException('Cannot create isolated fixture'); }
    $GLOBALS['write_fixture'] = realpath($fixture);
    $GLOBALS['write_checks'] = 0;
    $GLOBALS['write_skips'] = 0;
    $GLOBALS['write_download_calls'] = 0;
    $GLOBALS['write_deletes'] = [];
    define('ABSPATH', $fixture . '/site/');
    define('WP_CONTENT_DIR', ABSPATH . 'wp-content');
    define('WP_PLUGIN_DIR', WP_CONTENT_DIR . '/plugins');
    define('WPMU_PLUGIN_DIR', WP_CONTENT_DIR . '/mu-plugins');
    define('WPINC', 'wp-includes');
    define('MINUTE_IN_SECONDS', 60);
    final class StopActivation extends RuntimeException {}
    final class WP_Error { public function __construct(public string $code, public string $message = '') {} }
    function writeCheck(bool $condition, string $message): void
    {
        $GLOBALS['write_checks']++;
        if (!$condition) { throw new RuntimeException('FAIL: ' . $message); }
    }
    function ownWriteFixture(string $path): void
    {
        $normalised = str_replace('\\', '/', $path);
        $root = str_replace('\\', '/', $GLOBALS['write_fixture']);
        if ($normalised !== $root && !str_starts_with($normalised, $root . '/')) {
            throw new RuntimeException('Refusing to modify a path outside the owned fixture');
        }
    }
    function writeFixture(string $path, string $bytes): void
    {
        ownWriteFixture($path);
        if (!is_dir(dirname($path))) { mkdir(dirname($path), 0700, true); }
        file_put_contents($path, $bytes);
    }
    function removeWriteFixture(string $path): void
    {
        ownWriteFixture($path);
        if (is_link($path) || is_file($path)) { unlink($path); return; }
        if (!is_dir($path)) { return; }
        foreach (new DirectoryIterator($path) as $entry) {
            if (!$entry->isDot()) { removeWriteFixture($entry->getPathname()); }
        }
        rmdir($path);
    }
    function wp_mkdir_p(string $target): bool
    { ownWriteFixture($target); return is_dir($target) || mkdir($target, 0700, true); }
    function plugin_dir_path(string $path): string { return dirname($path) . '/'; }
    function plugin_dir_url(string $path): string { return 'https://fixture.invalid/plugins/'; }
    function plugin_basename(string $path): string { return 'hmdg-security-pro/hmdg-security-pro.php'; }
    function register_activation_hook(string $path, callable $callback): void { $GLOBALS['write_activate'] = $callback; }
    function register_deactivation_hook(string $path, callable $callback): void { $GLOBALS['write_deactivate'] = $callback; }
    function add_action(string $hook, callable $callback, int $priority = 10, int $args = 1): void {}
    function add_filter(string $hook, callable $callback, int $priority = 10, int $args = 1): void {}
    function remove_filter(string $hook, callable $callback, int $priority = 10): void {}
    function get_option(string $name, mixed $default = false): mixed { throw new StopActivation(); }
    function wp_upload_dir(?string $time = null, bool $create_dir = true): array
    {
        writeCheck(!$create_dir, 'uploads lookup does not create directories before the write guard');
        return ['basedir' => $GLOBALS['write_uploads']];
    }
    function get_temp_dir(): string { return $GLOBALS['write_temp_dir'] . '/'; }
    function is_admin(): bool { return true; }
    function wp_doing_cron(): bool { return false; }
    function is_wp_error(mixed $value): bool { return $value instanceof WP_Error; }
    function download_url(string $url, int $timeout = 300): string|WP_Error
    {
        $GLOBALS['write_download_calls']++;
        return $GLOBALS['write_download_result'] ?? new WP_Error('fixture_download');
    }
    function wp_delete_file(string $path): void
    {
        ownWriteFixture($path);
        $GLOBALS['write_deletes'][] = $path;
        if (is_file($path)) { unlink($path); }
    }
}
namespace HMDG\Security\Compatibility {
    final class HmdgHelpersCompat { public static function is_activation_request(): bool { return false; } }
}
namespace HMDG\Security\Services {
    /** Inject real partial-write/rename failures only for the helper's owned temp file. */
    function fwrite($stream, string $bytes): int|false
    {
        $path = stream_get_meta_data($stream)['uri'];
        if (str_contains(basename($path), '.hmdg-write-')) {
            $GLOBALS['write_temporary_modes'][] = fileperms($path) & 0777;
        }
        if (str_contains(basename($path), '.hmdg-write-') && ($GLOBALS['write_failure'] ?? null) === 'partial') {
            $GLOBALS['write_failure'] = 'stalled';
            return \fwrite($stream, substr($bytes, 0, 5));
        }
        if (str_contains(basename($path), '.hmdg-write-') && ($GLOBALS['write_failure'] ?? null) === 'stalled') {
            return 0;
        }
        return \fwrite($stream, $bytes);
    }
    function rename(string $from, string $to): bool
    {
        if (str_contains(basename($from), '.hmdg-write-') && ($GLOBALS['write_failure'] ?? null) === 'rename') {
            return false;
        }
        // Windows may refuse replacing an open target; retain and assert its old bytes.
        return @\rename($from, $to);
    }
    final class BuilderDetectionService
    {
        public function getActiveBuilders(): array { return []; }
        public function isElementorInstalled(): bool { return false; }
    }
    final class ObjectCacheService {}
    final class AlertService {}
    final class CronService
    {
        public function __construct(mixed ...$args) {}
        public function deactivate(): void {}
    }
}
namespace {
    require_once __DIR__ . '/../hmdg-security-pro.php';

    use HMDG\Security\Modules\ElementorSecurity;
    use HMDG\Security\Modules\FileIntegrity;
    use HMDG\Security\SecurityConfig;
    use HMDG\Security\Services\AlertService;
    use HMDG\Security\Services\BuilderDetectionService;
    use HMDG\Security\Services\LogService;
    use HMDG\Security\Services\ProtectedRootPaths;
    use HMDG\Security\Services\ReleaseMetadata;
    use HMDG\Security\Services\SignedReleasePackage;
    use HMDG\Security\Services\SafeFileWriter;

    function configuredLog(string $path): LogService
    {
        $reflection = new ReflectionClass(LogService::class);
        $log = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('logPath')->setValue($log, $path);
        $reflection->getProperty('logDir')->setValue($log, dirname($path));
        $reflection->getProperty('builderDetection')->setValue($log, new BuilderDetectionService());
        return $log;
    }
    function checksumWrite(string $path, LogService $log): void
    {
        $configReflection = new ReflectionClass(SecurityConfig::class);
        $config = $configReflection->newInstanceWithoutConstructor();
        $configReflection->getProperty('checksumFilePath')->setValue($config, $path);
        $reflection = new ReflectionClass(FileIntegrity::class);
        $integrity = $reflection->newInstanceWithoutConstructor();
        $reflection->getProperty('config')->setValue($integrity, $config);
        $reflection->getProperty('logService')->setValue($integrity, $log);
        $reflection->getMethod('writeChecksumFile')->invoke($integrity, ['files' => ['fixture.php' => 'fixture']]);
    }
    function activationWrites(string $uploads): void
    {
        $GLOBALS['write_uploads'] = $uploads;
        try { ($GLOBALS['write_activate'])(); } catch (StopActivation) {}
    }
    function svgWrite(string $path, LogService $log): void
    {
        $module = new ElementorSecurity(new SecurityConfig(), new AlertService(), $log, new BuilderDetectionService());
        $module->sanitiseSvgAfterUpload(['file' => $path, 'type' => 'image/svg+xml', 'url' => 'https://fixture.invalid/file.svg']);
    }

    try {
        $svg = '<svg><script>fixture()</script><path /></svg>';
        $protected = ['wp-config.php', 'index.php', '.htaccess', 'root.svg',
            'wp-admin/includes/fixture.php', 'wp-includes/fixture.php'];
        foreach ($protected as $relative) { writeFixture(ABSPATH . $relative, $svg); }
        writeFixture($fixture . '/wp-config.php', $svg);
        writeFixture(WP_PLUGIN_DIR . '/fixture/index.php', '<?php // fixture');
        $before = [];
        foreach ($protected as $relative) { $before[$relative] = hash_file('sha256', ABSPATH . $relative); }
        $parentBefore = hash_file('sha256', $fixture . '/wp-config.php');
        $data = WP_CONTENT_DIR . '/hmdg-security-pro';
        $log = configuredLog($data . '/security.log');

        activationWrites(WP_CONTENT_DIR . '/uploads');
        writeCheck(is_file($data . '/.htaccess') && is_file($data . '/index.php'), 'ordinary activation creates protection files');
        writeCheck(str_contains(file_get_contents(WP_CONTENT_DIR . '/uploads/.htaccess'), '# BEGIN HMDG Security'), 'ordinary uploads hardening remains functional');
        ($GLOBALS['write_deactivate'])();
        writeCheck(!str_contains(file_get_contents(WP_CONTENT_DIR . '/uploads/.htaccess'), '# BEGIN HMDG Security'), 'ordinary uploads deactivation remains functional');
        foreach ([ABSPATH, ABSPATH . 'wp-admin', ABSPATH . 'wp-includes'] as $directory) {
            activationWrites($directory);
            ($GLOBALS['write_deactivate'])();
        }

        $log->info('Fixture', 'ordinary log append');
        writeCheck(str_contains(file_get_contents($data . '/security.log'), 'ordinary log append'), 'ordinary logging appends');
        writeFixture($data . '/security.log', str_repeat('x', 5 * 1024 * 1024));
        configuredLog($data . '/security.log')->info('Fixture', 'after normal rotation');
        writeCheck(filesize($data . '/security.log.1') === 5 * 1024 * 1024, 'ordinary log rotation remains functional');
        checksumWrite($data . '/checksums.json', $log);
        writeCheck(json_decode(file_get_contents($data . '/checksums.json'), true)['files']['fixture.php'] === 'fixture', 'ordinary checksum write remains functional');
        $baselinePath = $data . '/checksums.json';
        $baselineBytes = file_get_contents($baselinePath);
        foreach (['partial', 'rename'] as $failure) {
            $GLOBALS['write_failure'] = $failure;
            $started = hrtime(true);
            writeCheck(!SafeFileWriter::replace($baselinePath, '{"replacement":"must never be published partially"}'),
                'injected write/rename failure reports refusal');
            $GLOBALS['write_failure'] = null;
            writeCheck((hrtime(true) - $started) < 2_000_000_000, 'write failure returns without waiting or retrying');
            writeCheck(file_get_contents($baselinePath) === $baselineBytes, 'failure preserves the previous complete baseline');
            writeCheck(glob($data . '/.hmdg-write-*.tmp') === [], 'failure removes only its own temporary file');
        }
        $held = fopen($baselinePath, 'rb');
        writeCheck(flock($held, LOCK_EX | LOCK_NB), 'fixture holds an actual baseline-file lock');
        try {
            $started = hrtime(true);
            $replacement = '{"files":{"complete":"replacement"}}';
            $replaced = SafeFileWriter::replace($baselinePath, $replacement);
            writeCheck((hrtime(true) - $started) < 2_000_000_000, 'held baseline lock never causes a lock wait');
        } finally { flock($held, LOCK_UN); fclose($held); }
        writeCheck(file_get_contents($baselinePath) === ($replaced ? $replacement : $baselineBytes),
            'held-lock replacement either publishes complete bytes or retains complete old bytes');
        writeCheck(glob($data . '/.hmdg-write-*.tmp') === [], 'held-lock replacement leaves no temporary files');
        $permissions = fileperms($baselinePath) & 0777;
        writeCheck(SafeFileWriter::replace($baselinePath, $baselineBytes), 'baseline remains writable after contention');
        clearstatcache(true, $baselinePath);
        writeCheck((fileperms($baselinePath) & 0777) === $permissions, 'atomic replacement preserves existing permissions');

        $appendPath = $data . '/append-lock.log';
        writeFixture($appendPath, "before\n");
        $held = fopen($appendPath, 'ab');
        writeCheck(flock($held, LOCK_EX | LOCK_NB), 'fixture holds an actual log-file lock');
        // NTFS locks are mandatory: a non-locking append may fail immediately there.
        set_error_handler(static fn (): bool => PHP_OS_FAMILY === 'Windows');
        try {
            $started = hrtime(true);
            $appended = SafeFileWriter::append($appendPath, "after\n");
            writeCheck((hrtime(true) - $started) < 2_000_000_000, 'best-effort append does not request or wait for an advisory lock');
            writeCheck(PHP_OS_FAMILY === 'Windows' || $appended, 'advisory file lock does not prevent the one-shot append');
        } finally { restore_error_handler(); flock($held, LOCK_UN); fclose($held); }
        $appendBytes = file_get_contents($appendPath);
        writeCheck(!SafeFileWriter::append($appendPath, str_repeat('x', 65537)), 'oversized log entries are dropped intact');
        writeCheck(file_get_contents($appendPath) === $appendBytes, 'oversized entry does not truncate or corrupt an existing log');
        $uploadSvg = WP_CONTENT_DIR . '/uploads/fixture.svg';
        writeFixture($uploadSvg, $svg);
        svgWrite($uploadSvg, $log);
        writeCheck(!str_contains(file_get_contents($uploadSvg), '<script>'), 'ordinary SVG upload is still sanitised');

        foreach (array_merge(array_map(static fn (string $relative): string => ABSPATH . $relative, $protected),
            [$fixture . '/wp-config.php', ABSPATH . 'absent-root.php', ABSPATH . 'wp-includes/missing/deep.php']) as $path) {
            writeCheck(!ProtectedRootPaths::allowsWrite($path), 'root/core write destination refused');
            configuredLog($path)->info('Fixture', 'must never append to root/core');
            checksumWrite($path, $log);
            svgWrite($path, $log);
        }
        writeCheck(!file_exists(ABSPATH . 'absent-root.php') && !file_exists(ABSPATH . 'wp-includes/missing'), 'absent protected files/directories remain absent');

        $hardLink = WP_CONTENT_DIR . '/uploads/linked.svg';
        if (link(ABSPATH . 'wp-config.php', $hardLink)) {
            writeCheck(!ProtectedRootPaths::allowsWrite($hardLink), 'hard-linked files cannot edit another protected name');
            svgWrite($hardLink, $log);
            configuredLog($hardLink)->info('Fixture', 'must not append through hard link');
            checksumWrite($hardLink, $log);
            removeWriteFixture($hardLink);
        } else { $GLOBALS['write_skips']++; }

        $alias = WP_CONTENT_DIR . '/uploads/root-alias.svg';
        if (@symlink(ABSPATH . 'wp-config.php', $alias)) {
            writeCheck(!ProtectedRootPaths::allowsWrite($alias), 'symlink to root config cannot be written');
            svgWrite($alias, $log); configuredLog($alias)->info('Fixture', 'blocked alias'); checksumWrite($alias, $log);
            removeWriteFixture($alias);
            writeCheck(symlink(ABSPATH . 'absent-config.php', $alias), 'dangling protected alias fixture created');
            writeCheck(!ProtectedRootPaths::allowsWrite($alias), 'dangling final alias cannot create a root file');
            checksumWrite($alias, $log); removeWriteFixture($alias);

            $directoryAlias = WP_CONTENT_DIR . '/uploads/core-alias';
            writeCheck(symlink(ABSPATH . 'wp-includes', $directoryAlias), 'core directory alias fixture created');
            checksumWrite($directoryAlias . '/missing/deep/checksums.json', $log);
            writeCheck(!file_exists(ABSPATH . 'wp-includes/missing'), 'nearest existing ancestor blocks creation through a core alias');
            activationWrites($directoryAlias); ($GLOBALS['write_deactivate'])();
            removeWriteFixture($directoryAlias);

            removeWriteFixture($data);
            writeCheck(symlink(ABSPATH, $data), 'data-directory alias fixture created');
            activationWrites(ABSPATH); ($GLOBALS['write_deactivate'])();
            configuredLog($data . '/wp-config.php')->info('Fixture', 'blocked data alias');
            checksumWrite($data . '/wp-config.php', $log);
            removeWriteFixture($data);
        } else {
            $GLOBALS['write_skips']++;
            echo "SKIP: native symlink write fixtures unavailable; Linux CI executes them.\n";
        }

        if (function_exists('sodium_crypto_sign_verify_detached') && class_exists(ZipArchive::class)) {
            $GLOBALS['write_temp_dir'] = ABSPATH;
            $calls = $GLOBALS['write_download_calls'];
            $result = SignedReleasePackage::download(ReleaseMetadata::packageUrl('1.12.0'), '');
            writeCheck($result instanceof WP_Error && $GLOBALS['write_download_calls'] === $calls,
                'root temporary directory is refused before download_url can create or delete files');
            $GLOBALS['write_temp_dir'] = $fixture . '/tmp';
            writeFixture($fixture . '/tmp/safe.zip', '');
            $GLOBALS['write_download_result'] = ABSPATH . 'wp-config.php';
            $result = SignedReleasePackage::download(ReleaseMetadata::packageUrl('1.12.0'), '');
            writeCheck($result instanceof WP_Error && $GLOBALS['write_deletes'] === [], 'redirected download result cannot delete a protected root file');
            $GLOBALS['write_download_result'] = $fixture . '/tmp/safe.zip';
            SignedReleasePackage::download(ReleaseMetadata::packageUrl('1.12.0'), '');
            writeCheck(!file_exists($fixture . '/tmp/safe.zip'), 'ordinary rejected temporary download is still cleaned');
        } else {
            $GLOBALS['write_skips']++;
            echo "SKIP: download preflight checks require sodium and zip extensions.\n";
        }

        foreach ($before as $relative => $hash) {
            writeCheck(is_file(ABSPATH . $relative) && hash_file('sha256', ABSPATH . $relative) === $hash,
                'protected file bytes unchanged: ' . $relative);
        }
        writeCheck(hash_file('sha256', $fixture . '/wp-config.php') === $parentBefore, 'parent config bytes unchanged');
        writeCheck(PHP_OS_FAMILY === 'Windows' || array_unique($GLOBALS['write_temporary_modes'] ?? []) === [0600],
            'unpublished temporary bytes remain private before their first write');
        echo 'Root/core write protection: ', $GLOBALS['write_checks'], ' checks passed; ', $GLOBALS['write_skips'], " group(s) skipped.\n";
    } finally {
        $resolved = realpath($fixture);
        $temporary = realpath(sys_get_temp_dir());
        if ($resolved === false || $temporary === false || dirname($resolved) !== $temporary
            || !str_starts_with(basename($resolved), 'hmdg-root-writes-')) {
            throw new RuntimeException('Refusing cleanup of an unverified fixture root');
        }
        removeWriteFixture($resolved);
    }
}
