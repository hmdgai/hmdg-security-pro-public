<?php

declare(strict_types=1);

/** Filesystem regression fixtures live only in an individually owned temporary directory. */
namespace {
    $fixture = sys_get_temp_dir() . '/hmdg-root-files-' . bin2hex(random_bytes(8));
    if (!mkdir($fixture, 0700)) { throw new \RuntimeException('Cannot create isolated fixture'); }
    $GLOBALS['root_fixture'] = realpath($fixture);
    $GLOBALS['root_checks'] = 0;
    $GLOBALS['root_skips'] = 0;
    $GLOBALS['root_deactivated'] = [];
    $GLOBALS['root_deleted'] = [];
    $GLOBALS['root_unlinked'] = [];
    $GLOBALS['root_fail_rename'] = null;
    $GLOBALS['root_fail_unlink'] = null;
    define('ABSPATH', $fixture . '/site/');
    define('WP_CONTENT_DIR', ABSPATH . 'wp-content');
    define('WP_PLUGIN_DIR', WP_CONTENT_DIR . '/plugins');
    define('WPINC', 'wp-includes');
    define('MINUTE_IN_SECONDS', 60);

    function fixtureOwns(string $path): void
    {
        $root = $GLOBALS['root_fixture'];
        $normalised = str_replace('\\', '/', $path);
        $normalisedRoot = str_replace('\\', '/', $root);
        if ($normalised !== $normalisedRoot && !str_starts_with($normalised, $normalisedRoot . '/')) {
            throw new \RuntimeException('Fixture operation refused outside owned directory');
        }
        $cursor = is_link($path) ? dirname($path) : $path;
        while (!file_exists($cursor)) { $cursor = dirname($cursor); }
        $resolved = str_replace('\\', '/', (string) realpath($cursor));
        if ($resolved !== $normalisedRoot && !str_starts_with($resolved, $normalisedRoot . '/')) {
            throw new \RuntimeException('Fixture operation refused through escaping ancestor');
        }
    }
    function fixtureWrite(string $path, string $bytes = '<?php // fixture'): void
    {
        fixtureOwns($path);
        if (!is_dir(dirname($path))) { mkdir(dirname($path), 0700, true); }
        if (file_put_contents($path, $bytes) === false) { throw new \RuntimeException('Fixture write failed'); }
    }
    function fixtureRemove(string $path): void
    {
        fixtureOwns($path);
        if (is_link($path) || is_file($path)) { unlink($path); return; }
        if (!is_dir($path)) { return; }
        foreach (new \DirectoryIterator($path) as $entry) {
            if (!$entry->isDot()) { fixtureRemove($entry->getPathname()); }
        }
        rmdir($path);
    }
    function check(bool $condition, string $message): void
    {
        $GLOBALS['root_checks']++;
        if (!$condition) { throw new \RuntimeException('FAIL: ' . $message); }
    }
    function wp_mkdir_p(string $path): bool
    {
        fixtureOwns($path);
        return is_dir($path) || mkdir($path, 0700, true);
    }
    function wp_json_encode(mixed $data, int $flags = 0): string|false { return json_encode($data, $flags); }
    function is_plugin_active(string $file): bool { return true; }
    function deactivate_plugins(string $file, bool $silent = false): void
    {
        check($silent, 'conflicting plugins are deactivated silently');
        $GLOBALS['root_deactivated'][] = $file;
    }
    function delete_plugins(array $files): never { throw new \RuntimeException('Vendor uninstall path must not run'); }
    function uninstall_plugin(string $file): never { throw new \RuntimeException('Vendor uninstall must not run'); }
    function wp_clean_plugins_cache(bool $clear = true): void { $GLOBALS['root_cache_cleared'] = true; }
    class WP_Filesystem_Direct
    {
        public function delete(string $path, bool $recursive = false, string|false $type = false): bool
        {
            check($recursive, 'only approved plugin-directory recursive removal is used');
            fixtureOwns($path);
            $GLOBALS['root_deleted'][] = $path;
            fixtureRemove($path);
            return !file_exists($path);
        }
    }
    function WP_Filesystem(array $args, string $context, bool $relaxed): bool
    {
        $GLOBALS['wp_filesystem'] = new WP_Filesystem_Direct();
        return true;
    }
}

namespace HMDG\Security {
    final class SecurityConfig { public string $alertEmail = 'fixture@example.invalid'; }
}

namespace HMDG\Security\Services {
    final class LogService
    {
        public array $entries = [];
        public function warning(string $module, string $message, array $context = []): void
        { $this->entries[] = [$module, $message, $context]; }
        public function info(string $module, string $message, array $context = []): void {}
    }
}

namespace HMDG\Security\Admin {
    final class FindingsRepository
    {
        public const STATUS_QUARANTINED = 'quarantined';
        public const STATUS_DELETED = 'deleted';
        public const STATUS_FALSE_POSITIVE = 'false_positive';
        public const STATUS_FLAGGED = 'flagged';
        public array $rows = [];
        public function insert(array $data): int
        { $id = count($this->rows) + 1; $this->rows[$id] = $data + ['id' => $id]; return $id; }
        public function findById(int $id): ?array { return $this->rows[$id] ?? null; }
        public function findByPathAndStatus(string $originalPath, string $status): ?array
        {
            foreach ($this->rows as $row) {
                if ($row['original_path'] === $originalPath && $row['status'] === $status) { return $row; }
            }
            return null;
        }
        public function updateStatus(int $id, string $newStatus, int $actionedBy = 0): bool
        { $this->rows[$id]['status'] = $newStatus; return true; }
    }
    function rename(string $from, string $to): bool
    {
        \fixtureOwns($from); \fixtureOwns($to);
        return $from !== $GLOBALS['root_fail_rename'] && \rename($from, $to);
    }
    function copy(string $from, string $to): bool
    { \fixtureOwns($from); \fixtureOwns($to); return \copy($from, $to); }
    function unlink(string $path): bool
    {
        \fixtureOwns($path);
        $GLOBALS['root_unlinked'][] = $path;
        return $path !== $GLOBALS['root_fail_unlink'] && \unlink($path);
    }
}

namespace {
    require_once __DIR__ . '/../includes/Detection/Severity.php';
    require_once __DIR__ . '/../includes/Services/ProtectedRootPaths.php';
    require_once __DIR__ . '/../includes/Services/SafeFileWriter.php';
    require_once __DIR__ . '/../includes/Admin/QuarantineService.php';
    require_once __DIR__ . '/../includes/Modules/ConflictCleaner.php';

    use HMDG\Security\Admin\FindingsRepository;
    use HMDG\Security\Admin\QuarantineService;
    use HMDG\Security\Detection\Severity;
    use HMDG\Security\Modules\ConflictCleaner;
    use HMDG\Security\Services\ProtectedRootPaths;

    $repository = new FindingsRepository();
    $service = new QuarantineService($repository, new HMDG\Security\Services\LogService());
    $quarantine = WP_CONTENT_DIR . '/hmdg-security-pro/quarantine';

    function archiveFinding(string $original, string $bytes = '<?php // archived fixture'): array
    {
        global $repository, $quarantine;
        $relative = '2000-01-01/fixture/' . bin2hex(random_bytes(4)) . '.php';
        $absolute = $quarantine . '/' . $relative;
        fixtureWrite($absolute, $bytes);
        $id = $repository->insert(['original_path' => $original, 'quarantine_path' => $relative,
            'status' => FindingsRepository::STATUS_QUARANTINED]);
        return [$id, $absolute];
    }
    function assertFlagged(string $path, string $original): void
    {
        global $service, $repository;
        $before = hash_file('sha256', $path);
        $id = $service->quarantine($path, Severity::HighRisk, [], 'fixture');
        check(is_int($id), 'protected HighRisk file remains visible as finding: ' . $original);
        check(is_file($path) && hash_file('sha256', $path) === $before, 'protected file remains unchanged: ' . $original);
        check($repository->rows[$id]['status'] === FindingsRepository::STATUS_FLAGGED, 'protected finding needs manual review');
        check($repository->rows[$id]['quarantine_path'] === null, 'protected finding never records a moved file');
        check($repository->rows[$id]['original_path'] === $original, 'protected finding retains correct original path');
    }
    function pluginFixture(): array
    {
        $plugin = (new \ReflectionClass(ConflictCleaner::class))->getConstant('CONFLICTING_PLUGINS')[1];
        fixtureWrite(WP_PLUGIN_DIR . '/' . $plugin['file'], "<?php\n/**\n * Plugin Name: Wordfence Security\n */\n");
        fixtureWrite(WP_PLUGIN_DIR . '/wordfence/lib/fixture.php');
        return $plugin;
    }
    function processFixture(array $plugin): array
    {
        $cleaner = new ConflictCleaner(new HMDG\Security\SecurityConfig(), new HMDG\Security\Services\LogService());
        return (new \ReflectionMethod($cleaner, 'processPlugin'))->invoke($cleaner, $plugin, [$plugin['file'] => ['Version' => 'fixture']]);
    }
    function assertRemovalRefused(array $plugin): void
    {
        $before = [count($GLOBALS['root_deactivated']), count($GLOBALS['root_deleted'])];
        $result = processFixture($plugin);
        check($result['status'] === 'skipped', 'linked or protected plugin tree is skipped');
        check($before === [count($GLOBALS['root_deactivated']), count($GLOBALS['root_deleted'])], 'unsafe tree is neither deactivated nor deleted');
    }

    try {
        fixtureWrite(WP_PLUGIN_DIR . '/ordinary/plugin.php');
        foreach (['wp-config.php', 'index.php', 'wp-load.php', 'xmlrpc.php', '.htaccess', 'readme.html', 'custom-root.txt',
            'wp-admin/includes/core-fixture.php', 'wp-admin/core-asset.css', 'wp-includes/core-fixture.php', 'wp-includes/assets/core.js'] as $relative) {
            fixtureWrite(ABSPATH . $relative);
            assertFlagged(ABSPATH . $relative, $relative);
        }
        assertFlagged(ABSPATH . 'wp-content/../index.php', 'index.php');
        fixtureWrite($fixture . '/wp-config.php');
        assertFlagged($fixture . '/wp-config.php', '../wp-config.php');

        $configPath = ABSPATH . 'wp-config.php';
        $oldHash = hash_file('sha256', $configPath);
        $baselinePath = WP_CONTENT_DIR . '/hmdg-security-pro/checksums.json';
        fixtureWrite($baselinePath, json_encode(['files' => ['wp-config.php' => $oldHash]], JSON_THROW_ON_ERROR));
        fixtureWrite($configPath, "<?php\ndefine('DB_NAME', 'fixture');\nrequire_once ABSPATH . 'wp-settings.php';\n");
        $hostRewriteHash = hash_file('sha256', $configPath);
        check($hostRewriteHash !== $oldHash, 'host rewrite differs from the stored baseline');
        for ($attempt = 0; $attempt < 2; $attempt++) {
            $id = $service->quarantine($configPath, Severity::HighRisk, [], 'file_integrity_scan');
            check(is_int($id) && $repository->rows[$id]['status'] === FindingsRepository::STATUS_FLAGGED,
                'repeated HighRisk config detections remain review-only');
            check(is_file($configPath) && hash_file('sha256', $configPath) === $hostRewriteHash,
                'rewritten config survives repeated detections without editing or moving');
        }
        check(json_decode(file_get_contents($baselinePath), true)['files']['wp-config.php'] === $oldHash,
            'config protection does not depend on silently trusting or updating its stale baseline');

        foreach (['missing-root.txt', './missing-root.php', 'wp-content/../missing-root.php', '../wp-config.php',
            'wp-admin/missing.php', 'wp-includes/nested/missing.css', 'wp-content/../wp-admin/nested/missing.php', ''] as $original) {
            [$id, $archived] = archiveFinding($original);
            check(!$service->deletePermanently($id, 1), 'legacy protected original cannot be permanently deleted: ' . $original);
            check(is_file($archived), 'protected archived copy is retained');
            check($repository->rows[$id]['status'] === FindingsRepository::STATUS_QUARANTINED, 'refusal preserves finding status');
        }

        $ordinary = WP_CONTENT_DIR . '/uploads/ordinary-fixture.php';
        fixtureWrite($ordinary);
        $id = $service->quarantine($ordinary, Severity::HighRisk, [], 'fixture');
        check(is_int($id) && !file_exists($ordinary), 'ordinary upload is still quarantined');
        check($repository->rows[$id]['status'] === FindingsRepository::STATUS_QUARANTINED, 'ordinary quarantine status unchanged');
        check($service->restore($id, 1) && is_file($ordinary), 'ordinary upload can still be restored');
        $id = $service->quarantine($ordinary, Severity::HighRisk, [], 'fixture');
        check($service->deletePermanently($id, 1), 'ordinary quarantine can still be permanently deleted');

        foreach (['restored-root.php', 'wp-admin/restored-fixture.php', 'wp-includes/restored-fixture.php'] as $relative) {
            [$id, $archived] = archiveFinding($relative, 'restored fixture');
            check(!$service->restore($id, 1), 'protected files are never created by restoration');
            check(!file_exists(ABSPATH . $relative) && is_file($archived), 'protected restoration leaves missing root/core destination untouched');
        }
        fixtureRemove($fixture . '/wp-config.php');
        [$id, $archived] = archiveFinding('../wp-config.php', 'restored parent config');
        check(!$service->restore($id, 1) && !file_exists($fixture . '/wp-config.php') && is_file($archived), 'missing parent config remains untouched');
        [$id, $archived] = archiveFinding('index.php', 'must not overwrite');
        $before = file_get_contents(ABSPATH . 'index.php');
        check(!$service->restore($id, 1) && is_file($archived), 'existing root file is never overwritten');
        check(file_get_contents(ABSPATH . 'index.php') === $before, 'existing root bytes are unchanged');

        [$id, $archived] = archiveFinding('fallback-root.php', 'retained fallback copy');
        $GLOBALS['root_fail_rename'] = realpath($archived);
        $GLOBALS['root_fail_unlink'] = realpath($archived);
        check(!$service->restore($id, 1), 'restore reports source-cleanup failure');
        check(is_file($archived) && !file_exists(ABSPATH . 'fallback-root.php'), 'refusal preserves quarantine evidence without creating a protected file');
        check(!in_array(ABSPATH . 'fallback-root.php', $GLOBALS['root_unlinked'], true), 'protected restore rollback never attempts root unlink');
        $GLOBALS['root_fail_rename'] = $GLOBALS['root_fail_unlink'] = null;

        $GLOBALS['wp_filesystem'] = new WP_Filesystem_Direct();
        $plugin = pluginFixture();
        fixtureWrite(WP_PLUGIN_DIR . '/wordfence/uninstall.php', '<?php throw new RuntimeException("must never execute vendor uninstall");');
        $result = processFixture($plugin);
        check($result['status'] === 'removed' && !is_dir(WP_PLUGIN_DIR . '/wordfence'), 'ordinary allowlisted plugin still removed without running vendor uninstall');
        check($GLOBALS['root_cache_cleared'] ?? false, 'native plugin discovery/update cache is invalidated');
        $plugin = pluginFixture();
        $GLOBALS['wp_filesystem'] = new \stdClass();
        assertRemovalRefused($plugin);
        $GLOBALS['wp_filesystem'] = new WP_Filesystem_Direct();

        $link = WP_CONTENT_DIR . '/uploads/root-link.php';
        fixtureOwns($link);
        if (@symlink(ABSPATH . 'index.php', $link)) {
            assertFlagged($link, 'index.php');
            check(is_link($link), 'nested alias to root is never moved');
            $target = WP_CONTENT_DIR . '/uploads/root-alias-target.php';
            fixtureWrite($target);
            $rootAlias = ABSPATH . 'root-alias.php';
            fixtureOwns($rootAlias);
            check(symlink($target, $rootAlias), 'fixture root alias created');
            assertFlagged($rootAlias, 'root-alias.php');
            assertFlagged($target, 'root-alias.php');

            $coreLink = WP_CONTENT_DIR . '/uploads/core-link.php';
            fixtureOwns($coreLink);
            check(symlink(ABSPATH . 'wp-admin/includes/core-fixture.php', $coreLink), 'fixture core alias created');
            assertFlagged($coreLink, 'wp-admin/includes/core-fixture.php');

            foreach ([ABSPATH => 'root-dir-link', ABSPATH . 'wp-admin' => 'core-dir-link', ABSPATH . 'index.php' => 'root-file-link',
                $fixture . '/missing-target' => 'broken-link'] as $target => $name) {
                $nestedLink = WP_PLUGIN_DIR . '/wordfence/' . $name;
                fixtureOwns($nestedLink);
                check(symlink($target, $nestedLink), 'nested conflict fixture link created');
                assertRemovalRefused($plugin);
                fixtureRemove($nestedLink);
            }
            $pluginAlias = ABSPATH . 'plugin-file-alias.php';
            fixtureOwns($pluginAlias);
            check(symlink(WP_PLUGIN_DIR . '/wordfence/lib/fixture.php', $pluginAlias), 'root alias into legitimate plugin created');
            assertRemovalRefused($plugin);
            fixtureRemove($pluginAlias);

            fixtureRemove(WP_PLUGIN_DIR . '/wordfence');
            fixtureWrite($fixture . '/external-plugin/wordfence.php', "<?php\n/**\n * Plugin Name: Wordfence Security\n */\n");
            $pluginLink = WP_PLUGIN_DIR . '/wordfence';
            fixtureOwns($pluginLink);
            check(symlink($fixture . '/external-plugin', $pluginLink), 'top-level conflict fixture link created');
            assertRemovalRefused($plugin);
            fixtureRemove($pluginLink);

            // A compromised quarantine-directory link must never turn an active root/core file into an archive.
            fixtureOwns($quarantine); fixtureOwns($fixture . '/quarantine-backup');
            check(rename($quarantine, $fixture . '/quarantine-backup'), 'quarantine fixture moved aside');
            check(symlink(ABSPATH, $quarantine), 'quarantine-to-root fixture link created');
            foreach (['index.php', 'wp-admin/includes/core-fixture.php', 'wp-includes/core-fixture.php'] as $active) {
                $id = $repository->insert(['original_path' => 'wp-content/uploads/corrupt-original.php',
                    'quarantine_path' => $active, 'status' => FindingsRepository::STATUS_QUARANTINED]);
                check(!$service->deletePermanently($id, 1), 'actual protected target wins over corrupt ordinary original');
                check(!$service->restore($id, 1), 'actual protected target is never moved out of active site on restore');
                check(is_file(ABSPATH . $active), 'active protected file survives compromised quarantine link');
            }
            fixtureRemove($quarantine);
            check(rename($fixture . '/quarantine-backup', $quarantine), 'quarantine fixture restored');
        } else {
            $GLOBALS['root_skips']++;
            echo "SKIP: native symlink fixtures unavailable on this host; Linux CI executes them.\n";
        }

        check(ProtectedRootPaths::isProtectedOriginal('wp-includes/not-yet-present/deep.php'), 'missing core-tree originals remain protected');
        check(!ProtectedRootPaths::isProtectedOriginal('wp-content/uploads/ordinary.php'), 'ordinary content paths remain actionable');
        echo 'Protected root/core files: ' . $GLOBALS['root_checks'] . ' checks passed; ' . $GLOBALS['root_skips'] . " symlink group(s) skipped.\n";
    } finally {
        $resolvedFixture = realpath($fixture);
        $tempRoot = realpath(sys_get_temp_dir());
        if ($resolvedFixture !== false && $tempRoot !== false
            && dirname($resolvedFixture) === $tempRoot
            && str_starts_with(basename($resolvedFixture), 'hmdg-root-files-')) {
            fixtureRemove($resolvedFixture);
        } else {
            throw new \RuntimeException('Refusing cleanup of an unverified fixture root');
        }
    }
}
