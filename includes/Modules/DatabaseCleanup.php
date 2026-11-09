<?php

declare(strict_types=1);

namespace HMDG\Security\Modules;

use HMDG\Security\Admin\LockoutLogRepository;
use HMDG\Security\SecurityConfig;
use HMDG\Security\Services\BuilderDetectionService;
use HMDG\Security\Services\CronService;
use HMDG\Security\Services\LogService;
use HMDG\Security\Services\ObjectCacheService;

/**
 * Scheduled database cleanup module for removing stale data without
 * disrupting Elementor or Divi page builder content.
 *
 * Cleans spam/trashed comments, expired transients, auto-drafts,
 * orphaned postmeta, and excess post revisions. Every query is
 * batch-limited to prevent long-running locks on production databases.
 *
 * Builder safety rules:
 * - NEVER deletes elementor_library or et_pb_layout post types.
 * - NEVER deletes _elementor_*, et_pb_*, or _et_pb_* meta keys.
 * - Retains more revisions for builder posts (configurable).
 *
 * Does NOT register hooks — runCleanup() is called by the cron
 * scheduler in Plugin.php via the hmdg_security_database_cleanup action.
 *
 * @since 1.0.0
 */
final class DatabaseCleanup
{
    /** Module identifier used in log entries. */
    private const MODULE = 'DatabaseCleanup';

    /** Post types that must never be cleaned or have revisions pruned. */
    private const PROTECTED_POST_TYPES = [
        'elementor_library',
        'et_pb_layout',
    ];

    /**
     * Job name for the overlap-lock key (`hmdg_<JOB_NAME>_lock`) and
     * matching CronService::HOOK_CLEANUP.
     */
    private const JOB_NAME = 'weekly_database_cleanup';

    /**
     * @param SecurityConfig          $config           Immutable plugin configuration.
     * @param LogService              $logService       Structured logging service.
     * @param BuilderDetectionService $builderDetection Builder detection for context logging.
     * @param ObjectCacheService      $cacheService     Object cache for the single-instance lock.
     * @param CronService             $cronService      Cron orchestration service.
     */
    public function __construct(
        private readonly SecurityConfig $config,
        private readonly LogService $logService,
        private readonly BuilderDetectionService $builderDetection,
        private readonly ObjectCacheService $cacheService,
        private readonly CronService $cronService,
        private readonly LockoutLogRepository $lockoutLog,
    ) {}

    /**
     * Execute all cleanup operations in sequence.
     *
     * Each operation is independently batched and logged. Failures in
     * one operation do not prevent subsequent operations from running.
     * After all deletions, affected tables are optimised to reclaim
     * disk space and rebuild indexes.
     */
    public function runCleanup(): void
    {
        // Last-line-of-defence: never execute cleanup work outside cron context.
        // WP-CLI is allowed for manual invocation via `wp cron event run`.
        if (!wp_doing_cron() && !(defined('WP_CLI') && WP_CLI)) {
            $this->logService->warning(
                module: self::MODULE,
                message: static::class . '::runCleanup called outside cron context — aborted',
            );
            return;
        }

        // Single-instance overlap lock via CronService.
        if (!$this->cronService->acquireLock(self::JOB_NAME)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Database cleanup already in progress — skipping this invocation',
            );
            return;
        }

        try {
            $this->runCleanupInner();
            $this->cronService->recordRun(CronService::HOOK_CLEANUP);
        } finally {
            $this->cronService->releaseLock(self::JOB_NAME);
        }
    }

    /**
     * Inner cleanup logic — wrapped by runCleanup() with single-instance lock.
     */
    private function runCleanupInner(): void
    {
        /** @var \wpdb $wpdb */
        global $wpdb;

        $this->logService->info(
            module: self::MODULE,
            message: 'Database cleanup started',
            context: [
                'batch_limit' => $this->config->cleanupBatchLimit,
                'comment_age_days' => $this->config->cleanupCommentAge,
                'auto_draft_age_days' => $this->config->cleanupAutoDraftAge,
                'revisions_standard' => $this->config->revisionsStandard,
                'revisions_builder' => $this->config->revisionsBuilder,
            ],
        );

        $stats = [
            'spam_comments' => 0,
            'trashed_comments' => 0,
            'expired_transients' => 0,
            'auto_drafts' => 0,
            'orphaned_postmeta' => 0,
            'excess_revisions' => 0,
            'expired_lockout_logs' => 0,
        ];

        $stats['spam_comments'] = $this->cleanSpamComments(wpdb: $wpdb);
        $stats['trashed_comments'] = $this->cleanTrashedComments(wpdb: $wpdb);
        $stats['expired_transients'] = $this->cleanExpiredTransients(wpdb: $wpdb);
        $stats['auto_drafts'] = $this->cleanAutoDrafts(wpdb: $wpdb);
        $stats['orphaned_postmeta'] = $this->cleanOrphanedPostmeta(wpdb: $wpdb);
        $stats['excess_revisions'] = $this->cleanExcessRevisions(wpdb: $wpdb);
        $stats['expired_lockout_logs'] = $this->lockoutLog->purgeOlderThan(days: 90);

        $this->optimizeTables(wpdb: $wpdb);

        $totalDeleted = array_sum($stats);

        $this->logService->info(
            module: self::MODULE,
            message: 'Database cleanup completed',
            context: [
                'total_rows_deleted' => $totalDeleted,
                ...$stats,
            ],
        );
    }

    // ── 1. Spam Comments ──────────────────────────────────────────────

    /**
     * Delete spam comments older than the configured retention period.
     *
     * @param \wpdb $wpdb WordPress database abstraction layer.
     *
     * @return int Number of rows deleted.
     */
    private function cleanSpamComments(\wpdb $wpdb): int
    {
        $cutoffDate = $this->getCutoffDate(days: $this->config->cleanupCommentAge);

        /** @var int|false $deleted */
        $deleted = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->comments} WHERE comment_approved = 'spam' AND comment_date < %s LIMIT %d",
                $cutoffDate,
                $this->config->cleanupBatchLimit,
            )
        );

        $count = $deleted !== false ? $deleted : 0;

        $this->logService->info(
            module: self::MODULE,
            message: 'Spam comments cleaned',
            context: [
                'rows_deleted' => $count,
                'cutoff_date' => $cutoffDate,
            ],
        );

        return $count;
    }

    // ── 2. Trashed Comments ───────────────────────────────────────────

    /**
     * Delete trashed comments older than the configured retention period.
     *
     * @param \wpdb $wpdb WordPress database abstraction layer.
     *
     * @return int Number of rows deleted.
     */
    private function cleanTrashedComments(\wpdb $wpdb): int
    {
        $cutoffDate = $this->getCutoffDate(days: $this->config->cleanupCommentAge);

        /** @var int|false $deleted */
        $deleted = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->comments} WHERE comment_approved = 'trash' AND comment_date < %s LIMIT %d",
                $cutoffDate,
                $this->config->cleanupBatchLimit,
            )
        );

        $count = $deleted !== false ? $deleted : 0;

        $this->logService->info(
            module: self::MODULE,
            message: 'Trashed comments cleaned',
            context: [
                'rows_deleted' => $count,
                'cutoff_date' => $cutoffDate,
            ],
        );

        return $count;
    }

    // ── 3. Expired Transients ─────────────────────────────────────────

    /**
     * Delete expired transients from the options table.
     *
     * First removes timeout entries whose expiry timestamp has passed,
     * then removes orphaned transient values whose corresponding timeout
     * entry no longer exists.
     *
     * @param \wpdb $wpdb WordPress database abstraction layer.
     *
     * @return int Total number of rows deleted across both queries.
     */
    private function cleanExpiredTransients(\wpdb $wpdb): int
    {
        $now = time();

        // Delete expired timeout entries
        /** @var int|false $deletedTimeouts */
        $deletedTimeouts = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_%%' AND option_value < %d LIMIT %d",
                $now,
                $this->config->cleanupBatchLimit,
            )
        );

        $timeoutCount = $deletedTimeouts !== false ? $deletedTimeouts : 0;

        // Delete orphaned transient values (timeout entry no longer exists)
        /** @var int|false $deletedValues */
        $deletedValues = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->options}
                WHERE option_name LIKE '_transient_%%'
                AND option_name NOT LIKE '_transient_timeout_%%'
                AND option_name NOT IN (
                    SELECT REPLACE(option_name, '_transient_timeout_', '_transient_')
                    FROM (SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_%%') AS t
                )
                LIMIT %d",
                $this->config->cleanupBatchLimit,
            )
        );

        $valueCount = $deletedValues !== false ? $deletedValues : 0;
        $totalCount = $timeoutCount + $valueCount;

        $this->logService->info(
            module: self::MODULE,
            message: 'Expired transients cleaned',
            context: [
                'timeout_entries_deleted' => $timeoutCount,
                'orphaned_values_deleted' => $valueCount,
                'total_rows_deleted' => $totalCount,
            ],
        );

        return $totalCount;
    }

    // ── 4. Auto-Draft Posts ───────────────────────────────────────────

    /**
     * Delete auto-draft posts older than the configured retention period.
     *
     * Excludes elementor_library and et_pb_layout post types to protect
     * builder template drafts that may appear as auto-drafts during
     * creation workflows.
     *
     * @param \wpdb $wpdb WordPress database abstraction layer.
     *
     * @return int Number of rows deleted.
     */
    private function cleanAutoDrafts(\wpdb $wpdb): int
    {
        $cutoffDate = $this->getCutoffDate(days: $this->config->cleanupAutoDraftAge);

        /** @var int|false $deleted */
        $deleted = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->posts}
                WHERE post_status = 'auto-draft'
                AND post_date < %s
                AND post_type != 'elementor_library'
                AND post_type != 'et_pb_layout'
                LIMIT %d",
                $cutoffDate,
                $this->config->cleanupBatchLimit,
            )
        );

        $count = $deleted !== false ? $deleted : 0;

        $this->logService->info(
            module: self::MODULE,
            message: 'Auto-draft posts cleaned',
            context: [
                'rows_deleted' => $count,
                'cutoff_date' => $cutoffDate,
                'excluded_post_types' => self::PROTECTED_POST_TYPES,
            ],
        );

        return $count;
    }

    // ── 5. Orphaned Postmeta ──────────────────────────────────────────

    /**
     * Delete postmeta entries whose parent post no longer exists.
     *
     * Preserves all builder-related meta keys (_elementor_*, et_pb_*,
     * _et_pb_*) even if the parent post is missing, as these may be
     * referenced by builder global settings or cross-post style systems.
     *
     * @param \wpdb $wpdb WordPress database abstraction layer.
     *
     * @return int Number of rows deleted.
     */
    private function cleanOrphanedPostmeta(\wpdb $wpdb): int
    {
        $postmetaTable = $wpdb->prefix . 'postmeta';
        $postsTable = $wpdb->prefix . 'posts';

        // MySQL permits LIMIT only for single-table DELETE statements.
        /** @var int|false $deleted */
        $deleted = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM %i
                WHERE NOT EXISTS (
                    SELECT 1 FROM %i AS p WHERE p.ID = %i.post_id
                )
                AND meta_key NOT LIKE '_elementor_%%'
                AND meta_key NOT LIKE 'et_pb_%%'
                AND meta_key NOT LIKE '_et_pb_%%'
                LIMIT %d",
                $postmetaTable,
                $postsTable,
                $postmetaTable,
                $this->config->cleanupBatchLimit,
            )
        );

        $count = $deleted !== false ? $deleted : 0;

        $this->logService->info(
            module: self::MODULE,
            message: 'Orphaned postmeta cleaned',
            context: [
                'rows_deleted' => $count,
                'protected_meta_prefixes' => ['_elementor_', 'et_pb_', '_et_pb_'],
            ],
        );

        return $count;
    }

    // ── 6. Excess Revisions ───────────────────────────────────────────

    /**
     * Prune excess post revisions using builder-aware retention limits.
     *
     * Standard posts retain the last N revisions (config->revisionsStandard).
     * Builder posts — those containing Divi shortcodes, Elementor comments,
     * or Elementor data meta — retain more (config->revisionsBuilder) to
     * preserve the richer edit history that visual builders generate.
     *
     * Revisions for elementor_library and et_pb_layout post types are
     * never deleted.
     *
     * @param \wpdb $wpdb WordPress database abstraction layer.
     *
     * @return int Total number of excess revisions deleted.
     */
    private function cleanExcessRevisions(\wpdb $wpdb): int
    {
        $totalDeleted = 0;

        // Get all parent post IDs that have revisions, excluding protected post types
        $protectedTypesPlaceholders = implode(
            separator: ', ',
            array: array_fill(start_index: 0, count: count(self::PROTECTED_POST_TYPES), value: '%s'),
        );

        /** @var list<object{post_parent: string}> $parentRows */
        $parentRows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT DISTINCT r.post_parent
                FROM {$wpdb->posts} r
                INNER JOIN {$wpdb->posts} p ON r.post_parent = p.ID
                WHERE r.post_type = 'revision'
                AND p.post_type NOT IN ({$protectedTypesPlaceholders})",
                ...self::PROTECTED_POST_TYPES,
            )
        );

        if ($parentRows === null || $parentRows === []) {
            $this->logService->info(
                module: self::MODULE,
                message: 'No revisions to prune',
                context: [],
            );

            return 0;
        }

        $batchRemaining = $this->config->cleanupBatchLimit;

        foreach ($parentRows as $row) {
            if ($batchRemaining <= 0) {
                break;
            }

            $parentId = (int) $row->post_parent;
            $isBuilder = $this->isBuilderPost(wpdb: $wpdb, postId: $parentId);
            $keepLimit = $isBuilder ? $this->config->revisionsBuilder : $this->config->revisionsStandard;

            // Get all revisions for this parent, ordered newest first
            /** @var list<object{ID: string}>|null $revisions */
            $revisions = $wpdb->get_results(
                $wpdb->prepare(
                    "SELECT ID FROM {$wpdb->posts}
                    WHERE post_parent = %d
                    AND post_type = 'revision'
                    ORDER BY post_date DESC",
                    $parentId,
                )
            );

            if ($revisions === null || count($revisions) <= $keepLimit) {
                continue;
            }

            // Collect IDs of revisions beyond the keep limit
            $excessRevisions = array_slice(array: $revisions, offset: $keepLimit);
            $excessIds = array_map(
                callback: static fn (object $rev): int => (int) $rev->ID,
                array: $excessRevisions,
            );

            // Limit to remaining batch allowance
            $idsToDelete = array_slice(array: $excessIds, offset: 0, length: $batchRemaining);

            if ($idsToDelete === []) {
                continue;
            }

            $placeholders = implode(
                separator: ', ',
                array: array_fill(start_index: 0, count: count($idsToDelete), value: '%d'),
            );

            // Delete the excess revisions
            /** @var int|false $deleted */
            $deleted = $wpdb->query(
                $wpdb->prepare(
                    "DELETE FROM {$wpdb->posts} WHERE ID IN ({$placeholders})",
                    ...$idsToDelete,
                )
            );

            $count = $deleted !== false ? $deleted : 0;
            $totalDeleted += $count;
            $batchRemaining -= $count;

            // Also clean up postmeta for deleted revisions
            if ($count > 0) {
                $wpdb->query(
                    $wpdb->prepare(
                        "DELETE FROM {$wpdb->postmeta} WHERE post_id IN ({$placeholders})",
                        ...$idsToDelete,
                    )
                );
            }
        }

        $this->logService->info(
            module: self::MODULE,
            message: 'Excess revisions cleaned',
            context: [
                'rows_deleted' => $totalDeleted,
                'parents_checked' => count($parentRows),
                'standard_keep_limit' => $this->config->revisionsStandard,
                'builder_keep_limit' => $this->config->revisionsBuilder,
            ],
        );

        return $totalDeleted;
    }

    // ── 7. Table Optimisation ─────────────────────────────────────────

    /**
     * Run OPTIMIZE TABLE on the three tables most affected by cleanup.
     *
     * Reclaims disk space from deleted rows and rebuilds table indexes.
     * OPTIMIZE is a no-op on InnoDB when innodb_file_per_table is off,
     * but runs a table rebuild when it is on (the default on most hosts).
     *
     * @param \wpdb $wpdb WordPress database abstraction layer.
     */
    private function optimizeTables(\wpdb $wpdb): void
    {
        $tables = [
            $wpdb->comments,
            $wpdb->options,
            $wpdb->postmeta,
        ];

        foreach ($tables as $table) {
            // Use %i (WP 6.2+ identifier placeholder) for defensive coding.
            // Table names come from $wpdb properties (trusted) but the
            // pattern of string-interpolating into SQL is one we don't want
            // to set as precedent.
            $wpdb->query($wpdb->prepare('OPTIMIZE TABLE %i', $table));
        }

        $this->logService->info(
            module: self::MODULE,
            message: 'Table optimisation completed',
            context: ['tables' => $tables],
        );
    }

    // ── Private Helpers ───────────────────────────────────────────────

    /**
     * Determine whether a post was built with a page builder.
     *
     * A post is considered a "builder post" if any of the following are true:
     * - Its content contains Divi shortcodes ('[et_pb_')
     * - Its content contains an Elementor block comment ('<!-- wp:elementor')
     * - It has _elementor_data in its postmeta
     *
     * @param \wpdb $wpdb   WordPress database abstraction layer.
     * @param int   $postId The post ID to check.
     *
     * @return bool True if the post was built with Elementor or Divi.
     */
    private function isBuilderPost(\wpdb $wpdb, int $postId): bool
    {
        // Check post_content for builder markers
        /** @var string|null $content */
        $content = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT post_content FROM {$wpdb->posts} WHERE ID = %d",
                $postId,
            )
        );

        if ($content !== null) {
            // Divi shortcodes
            if (str_contains($content, '[et_pb_')) {
                return true;
            }

            // Elementor block comments
            if (str_contains($content, '<!-- wp:elementor')) {
                return true;
            }
        }

        // Check for _elementor_data meta key
        /** @var string|null $elementorMeta */
        $elementorMeta = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT meta_id FROM {$wpdb->postmeta}
                WHERE post_id = %d
                AND meta_key = '_elementor_data'
                LIMIT 1",
                $postId,
            )
        );

        return $elementorMeta !== null;
    }

    /**
     * Calculate a cutoff date string for cleanup queries.
     *
     * Returns a MySQL-compatible datetime string representing the moment
     * N days before now in UTC.
     *
     * @param int $days Number of days to subtract from the current time.
     *
     * @return string MySQL datetime string (Y-m-d H:i:s).
     */
    private function getCutoffDate(int $days): string
    {
        return (new \DateTimeImmutable(
            datetime: 'now',
            timezone: new \DateTimeZone(timezone: 'UTC'),
        ))->modify("-{$days} days")->format('Y-m-d H:i:s');
    }
}
