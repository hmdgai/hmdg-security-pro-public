<?php

declare(strict_types=1);

/**
 * Exercise the real cleanup method without booting WordPress or accessing a site.
 *
 * Optional integration: set HMDG_CLEANUP_TEST_DSN to a disposable MySQL database,
 * plus HMDG_CLEANUP_TEST_USER/PASSWORD, and enable pdo_mysql. Fixture tables have
 * randomized names and are removed afterwards. --emit-sql prints the actual SQL.
 */
namespace {
    define('WP_CONTENT_DIR', '/fictional-wordpress/wp-content');

    function wp_doing_cron(): bool { return false; }

    final class wpdb
    {
        public string $preparedFormat = '';
        public array $preparedArguments = [];
        public array $queries = [];
        public string $last_error = '';
        public int|false $result = 0;

        public function __construct(public string $prefix, private readonly ?PDO $connection = null) {}

        /** Only the identifier/integer placeholders used by this cleanup method. */
        public function prepare(string $query, int|string ...$arguments): string
        {
            $this->preparedFormat = $query;
            $this->preparedArguments = $arguments;
            $index = 0;
            $prepared = preg_replace_callback('/%%|%[id]/', static function (array $match) use ($arguments, &$index): string {
                if ($match[0] === '%%') { return '%'; }
                $value = $arguments[$index++];
                return $match[0] === '%i'
                    ? '`' . str_replace('`', '``', (string) $value) . '`'
                    : (string) (int) $value;
            }, $query);
            if ($prepared === null || $index !== count($arguments)) {
                throw new RuntimeException('Invalid cleanup query placeholders');
            }
            return $prepared;
        }

        public function query(string $query): int|false
        {
            $this->queries[] = $query;
            if ($this->connection === null) { return $this->result; }
            try {
                $this->last_error = '';
                return $this->connection->exec($query);
            } catch (PDOException $error) {
                $this->last_error = $error->getMessage();
                return false;
            }
        }
    }
}

namespace HMDG\Security\Services {
    class LogService
    {
        public array $entries = [];
        public function info(string $module, string $message, array $context = []): void
        {
            $this->entries[] = compact('module', 'message', 'context');
        }
        public function warning(string $module, string $message, array $context = []): void
        {
            $this->entries[] = compact('module', 'message', 'context');
        }
    }
    class BuilderDetectionService {}
    class ObjectCacheService {}
    class CronService {}
}

namespace HMDG\Security\Admin { class LockoutLogRepository {} }

namespace {
    require_once __DIR__ . '/../includes/SecurityConfig.php';
    require_once __DIR__ . '/../includes/Modules/DatabaseCleanup.php';

    use HMDG\Security\Admin\LockoutLogRepository;
    use HMDG\Security\Modules\DatabaseCleanup;
    use HMDG\Security\SecurityConfig;
    use HMDG\Security\Services\BuilderDetectionService;
    use HMDG\Security\Services\CronService;
    use HMDG\Security\Services\LogService;
    use HMDG\Security\Services\ObjectCacheService;

    $checks = 0;
    function cleanupCheck(bool $condition, string $message): void
    {
        $GLOBALS['checks']++;
        if (!$condition) { throw new RuntimeException('FAIL: ' . $message); }
    }

    function newCleanup(LogService $log): DatabaseCleanup
    {
        return new DatabaseCleanup(
            new SecurityConfig(), $log, new BuilderDetectionService(),
            new ObjectCacheService(), new CronService(), new LockoutLogRepository(),
        );
    }

    function cleanOrphans(DatabaseCleanup $cleanup, wpdb $database): int
    {
        return (new ReflectionMethod($cleanup, 'cleanOrphanedPostmeta'))->invoke($cleanup, $database);
    }

    if (in_array('--emit-sql', $argv, true)) {
        $database = new wpdb('hmdg_test_7_');
        cleanOrphans(newCleanup(new LogService()), $database);
        echo $database->queries[0], ";\n";
        exit(0);
    }

    cleanupCheck((new SecurityConfig())->cleanupBatchLimit === 500, 'default cleanup batch remains 500');
    foreach (['wp_', 'agency_', 'agency_7_', 'agency`_'] as $prefix) {
        $database = new wpdb($prefix);
        $database->result = 37;
        $log = new LogService();
        $count = cleanOrphans(newCleanup($log), $database);
        cleanupCheck($count === 37, 'affected rows are returned for ' . $prefix);
        cleanupCheck($database->preparedArguments === [
            $prefix . 'postmeta', $prefix . 'posts', $prefix . 'postmeta', 500,
        ], 'prefix-derived identifiers and batch use WordPress prepare for ' . $prefix);
        cleanupCheck(count($database->queries) === 1, 'one bounded statement per invocation for ' . $prefix);
        cleanupCheck($log->entries[0]['context'] === [
            'rows_deleted' => 37,
            'protected_meta_prefixes' => ['_elementor_', 'et_pb_', '_et_pb_'],
        ], 'existing cleanup statistics and builder protection log remain intact');
    }

    foreach ([0, false] as $result) {
        $database = new wpdb('wp_');
        $database->result = $result;
        $log = new LogService();
        cleanupCheck(cleanOrphans(newCleanup($log), $database) === 0, 'empty/error result returns zero');
        cleanupCheck($log->entries[0]['context']['rows_deleted'] === 0, 'empty/error result logs zero');
    }

    $wpdb = new wpdb('wp_');
    newCleanup(new LogService())->runCleanup();
    cleanupCheck($wpdb->queries === [], 'public cleanup entry point performs no queries outside cron/CLI');

    $dsn = getenv('HMDG_CLEANUP_TEST_DSN');
    if ($dsn === false || $dsn === '') {
        echo $checks, " cleanup checks passed; MySQL integration skipped (HMDG_CLEANUP_TEST_DSN unset).\n";
        exit(0);
    }
    if (!str_starts_with($dsn, 'mysql:')) {
        throw new RuntimeException('Integration requires a disposable MySQL/MariaDB database');
    }
    $connection = new PDO(
        $dsn, getenv('HMDG_CLEANUP_TEST_USER') ?: 'root', getenv('HMDG_CLEANUP_TEST_PASSWORD') ?: '',
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
    );
    $fixturePrefix = 'hmdg_cleanup_test_' . bin2hex(random_bytes(5)) . '_';
    foreach (['wp_', 'agency_', 'agency_7_'] as $suffix) {
        $prefix = $fixturePrefix . $suffix;
        $posts = '`' . $prefix . 'posts`';
        $postmeta = '`' . $prefix . 'postmeta`';
        try {
            $connection->exec("CREATE TABLE {$posts} (ID BIGINT UNSIGNED PRIMARY KEY) ENGINE=InnoDB");
            $connection->exec("CREATE TABLE {$postmeta} (
                meta_id BIGINT UNSIGNED PRIMARY KEY, post_id BIGINT UNSIGNED NULL,
                meta_key VARCHAR(255) NULL, meta_value LONGTEXT NULL, KEY post_id (post_id)
            ) ENGINE=InnoDB");
            $connection->exec("INSERT INTO {$posts} (ID) VALUES (1), (2)");
            $insert = $connection->prepare("INSERT INTO {$postmeta} VALUES (?, ?, ?, ?)");
            $connection->beginTransaction();
            // 503 eligible orphans exercise a full batch, its remainder, then no-op.
            for ($id = 1; $id <= 503; $id++) {
                $insert->execute([$id, 10000 + $id, 'ordinary_meta', 'orphan']);
            }
            $preserved = [
                [1001, 1, 'ordinary_meta', 'existing parent'],
                [1002, 2, '_elementor_data', 'existing builder parent'],
                [1003, 9999, '_elementor_data', 'orphaned Elementor data'],
                [1004, 9999, '_elementor_css', 'orphaned Elementor CSS'],
                [1005, 9999, 'et_pb_layout', 'orphaned Divi layout'],
                [1006, 9999, '_et_pb_use_builder', 'orphaned Divi flag'],
                [1007, 9999, '_elementor_', 'bare Elementor prefix'],
                [1008, 9999, 'et_pb_', 'bare Divi prefix'],
                [1009, 9999, '_et_pb_', 'bare underscored Divi prefix'],
                // Preserve the existing SQL LIKE underscore-wildcard semantics.
                [1010, 9999, 'XelementorYdata', 'existing Elementor pattern match'],
                [1011, 9999, 'etXpbYlayout', 'existing Divi pattern match'],
                [1012, 9999, 'XetYpbZlayout', 'existing underscored Divi pattern match'],
                [1013, 9999, null, 'existing NULL meta-key behavior'],
            ];
            foreach ($preserved as $row) { $insert->execute($row); }
            $connection->commit();

            $database = new wpdb($prefix, $connection);
            $log = new LogService();
            $cleanup = newCleanup($log);
            foreach ([500, 3, 0] as $expected) {
                cleanupCheck(cleanOrphans($cleanup, $database) === $expected,
                    'actual SQL deletes expected batch ' . $expected . ': ' . $database->last_error);
                cleanupCheck($database->last_error === '', 'database accepts the real prepared SQL');
                cleanupCheck(end($log->entries)['context']['rows_deleted'] === $expected,
                    'actual affected-row count is logged');
            }
            $remaining = $connection->query("SELECT meta_id, post_id, meta_key, meta_value FROM {$postmeta} ORDER BY meta_id")
                ->fetchAll(PDO::FETCH_NUM);
            // Drivers can return numeric columns as strings; compare values, including NULLs.
            cleanupCheck($remaining == $preserved, 'builder data and all existing-parent metadata remain unchanged');
            cleanupCheck((int) $connection->query("SELECT COUNT(*) FROM {$posts}")->fetchColumn() === 2,
                'parent posts remain unchanged');
        } finally {
            if ($connection->inTransaction()) { $connection->rollBack(); }
            $connection->exec("DROP TABLE IF EXISTS {$postmeta}");
            $connection->exec("DROP TABLE IF EXISTS {$posts}");
        }
    }
    echo $checks, ' cleanup checks passed against ', $connection->getAttribute(PDO::ATTR_SERVER_VERSION), ".\n";
}
