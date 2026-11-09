<?php

declare(strict_types=1);

namespace HMDG\Security\Admin;

use HMDG\Security\Detection\Severity;
use HMDG\Security\Detection\Signal;
use HMDG\Security\Services\LogService;
use HMDG\Security\Services\ProtectedRootPaths;

/**
 * Quarantine filesystem operations for v1.5.0.
 *
 * On HighRisk detection, AlertDispatcher calls quarantine() which:
 *   1. Keeps root/core files in place for review; validates other sources stay inside ABSPATH.
 *   2. Computes SHA-256 of file contents BEFORE moving.
 *   3. Builds a date-sharded quarantine target path.
 *   4. rename()s the file. On cross-filesystem failure, falls back to
 *      copy()+unlink(). If the unlink fails, aborts without deleting
 *      the source — leaving two copies is safer than leaving a dead
 *      quarantine row pointing to an empty directory while the
 *      malicious file still runs.
 *   5. Writes a sidecar JSON with original path + detection context.
 *   6. Inserts a FindingsRepository row.
 *
 * Quarantine layout:
 *   wp-content/hmdg-security-pro/quarantine/
 *     .htaccess         -- Deny from all
 *     index.php         -- Silence stub
 *     <yyyy-mm-dd>/
 *       <sha256-16>/
 *         <basename>        -- the quarantined file
 *         <basename>.json   -- metadata sidecar
 *
 * @security EVERY path operation is re-validated against its expected
 *           parent (ABSPATH for restore, quarantine dir for delete).
 *           No user-supplied path is ever passed to file functions
 *           without realpath() + str_starts_with() containment check.
 *
 * @since 1.5.0
 */
final class QuarantineService
{
    /** Module identifier used in log entries. */
    private const MODULE = 'QuarantineService';

    /** Length of the SHA-256 prefix used in quarantine path shards. */
    private const SHARD_PREFIX_LENGTH = 16;

    public function __construct(
        private readonly FindingsRepository $repository,
        private readonly LogService $logService,
    ) {}

    /**
     * Ensure the quarantine root exists with protection files.
     * Idempotent — safe to call from activation hook and on every
     * admin-context boot.
     */
    public function ensureDirectory(): bool
    {
        $root = $this->quarantineRoot();

        if ($root === null) {
            return false;
        }

        if (!is_dir($root)) {
            if (!wp_mkdir_p($root)) {
                $this->logService->warning(
                    module: self::MODULE,
                    message: 'Failed to create quarantine directory',
                    context: ['path' => $root],
                );
                return false;
            }
        }

        $htaccess = $root . '/.htaccess';
        if (!file_exists($htaccess)) {
            @file_put_contents(
                $htaccess,
                "# HMDG Security quarantine — no web access\nOrder deny,allow\nDeny from all\n",
                LOCK_EX,
            );
        }

        $indexStub = $root . '/index.php';
        if (!file_exists($indexStub)) {
            @file_put_contents($indexStub, '<?php // Silence is golden.', LOCK_EX);
        }

        return true;
    }

    /**
     * Move a file into quarantine and record a FindingsRepository row.
     *
     * @param list<Signal> $signals Signals that produced the finding.
     * @return int|null New finding row ID, or null on failure.
     */
    public function quarantine(
        string $absolutePath,
        Severity $severity,
        array $signals,
        string $source,
    ): ?int {
        if (ProtectedRootPaths::isProtected($absolutePath)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Protected WordPress root/core file retained in place for manual review',
                context: ['path' => $absolutePath],
            );
            return $this->flag($absolutePath, $severity, $signals, $source);
        }

        if (!$this->ensureDirectory()) {
            return null;
        }

        // Path containment — absolute path must resolve inside ABSPATH.
        $resolved = realpath($absolutePath);
        if ($resolved === false) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Quarantine skipped — source path does not resolve',
                context: ['path' => $absolutePath],
            );
            return null;
        }

        $abspath = $this->normalisePath(realpath(ABSPATH) ?: ABSPATH);
        $normalisedSource = $this->normalisePath($resolved);

        if (!str_starts_with($normalisedSource, $abspath)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Quarantine refused — source outside ABSPATH',
                context: ['path' => $resolved],
            );
            return null;
        }

        // Compute hash before moving.
        $hash = hash_file('sha256', $resolved);
        if ($hash === false) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Quarantine skipped — could not hash source',
                context: ['path' => $resolved],
            );
            return null;
        }

        $date    = gmdate('Y-m-d');
        $shard   = substr($hash, 0, self::SHARD_PREFIX_LENGTH);
        $baseDir = $this->quarantineRoot() . '/' . $date . '/' . $shard;

        if (!wp_mkdir_p($baseDir)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Failed to create quarantine shard directory',
                context: ['path' => $baseDir],
            );
            return null;
        }

        $basename       = basename($resolved);
        $targetFile     = $baseDir . '/' . $basename;
        $sidecarFile    = $baseDir . '/' . $basename . '.json';

        // If the target already exists from a prior run, append a suffix.
        $counter = 0;
        while (file_exists($targetFile)) {
            $counter++;
            $targetFile  = $baseDir . '/' . $basename . '.' . $counter;
            $sidecarFile = $baseDir . '/' . $basename . '.' . $counter . '.json';
        }

        $relativeOriginal = ltrim(substr($normalisedSource, strlen($abspath)), '/');
        $relativeQuarantine = $this->relativeFromContent(path: $targetFile);

        // Move the file. Prefer rename() (atomic on same FS).
        $moved = @rename($resolved, $targetFile);

        if (!$moved) {
            // Fallback for cross-filesystem or Windows dev.
            if (!@copy($resolved, $targetFile)) {
                $this->logService->warning(
                    module: self::MODULE,
                    message: 'Quarantine copy failed',
                    context: ['src' => $resolved, 'dst' => $targetFile],
                );
                return null;
            }
            if (!@unlink($resolved)) {
                // Do NOT delete the copy — leaving the malicious file in
                // place is safer than an orphan quarantine row. Log hard
                // and abort.
                $this->logService->warning(
                    module: self::MODULE,
                    message: 'Quarantine copied but source unlink failed — two copies exist; manual intervention required',
                    context: ['src' => $resolved, 'dst' => $targetFile],
                );
                return null;
            }
        }

        // Upsert: if an existing quarantined row points at the same
        // original path, close it (flag as superseded) then insert a
        // fresh row representing the current quarantined copy.
        $existing = $this->repository->findByPathAndStatus(
            originalPath: $relativeOriginal,
            status: FindingsRepository::STATUS_QUARANTINED,
        );
        if ($existing !== null && isset($existing['id'])) {
            $this->repository->updateStatus(
                id: (int) $existing['id'],
                newStatus: FindingsRepository::STATUS_DELETED,
                actionedBy: 0,
            );
        }

        [$topLabel, $topWeight, $categoryList] = $this->summariseSignals($signals);

        $sidecar = [
            'version'             => '1.5.0',
            'quarantined_at'      => gmdate('c'),
            'original_path'       => $relativeOriginal,
            'sha256'              => $hash,
            'severity'            => $severity->name,
            'severity_value'      => $severity->value,
            'source'              => $source,
            'top_signal_label'    => $topLabel,
            'top_signal_weight'   => $topWeight,
            'signal_categories'   => $categoryList,
        ];
        @file_put_contents(
            $sidecarFile,
            (string) wp_json_encode($sidecar, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
            LOCK_EX,
        );

        return $this->repository->insert([
            'created_at'        => gmdate('Y-m-d H:i:s'),
            'severity'          => $severity->value,
            'status'            => FindingsRepository::STATUS_QUARANTINED,
            'original_path'     => $relativeOriginal,
            'quarantine_path'   => $relativeQuarantine,
            'sha256'            => $hash,
            'top_signal_label'  => $topLabel,
            'top_signal_weight' => $topWeight,
            'signal_categories' => $categoryList,
            'source'            => $source,
        ]);
    }

    /**
     * v1.7.0 — record a Suspicious / NeedsReview finding in the admin
     * Quarantine table WITHOUT moving the file. HighRisk findings still
     * flow through quarantine() above; this path exists because
     * auto-quarantining borderline detections can break legitimate
     * sites (a false positive removes a real file). Flagging gives
     * operators a visible review queue parallel to the alert email.
     *
     * Idempotent: if a flagged row already exists for the same path,
     * the existing ID is returned and no new row is written — prevents
     * cron re-scans from creating duplicates on every run.
     *
     * @param list<Signal> $signals Signals that produced the finding.
     * @return int|null Existing or new finding row ID; null on refusal.
     */
    public function flag(
        string $absolutePath,
        Severity $severity,
        array $signals,
        string $source,
    ): ?int {
        $resolved = realpath($absolutePath);
        if ($resolved === false) {
            return null;
        }

        $relativeOriginal = ProtectedRootPaths::originalPath($absolutePath);
        if ($relativeOriginal === null) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Flag refused — source outside ABSPATH',
                context: ['path' => $resolved],
            );
            return null;
        }

        $hash = hash_file('sha256', $resolved);
        if ($hash === false) {
            return null;
        }

        $existing = $this->repository->findByPathAndStatus(
            originalPath: $relativeOriginal,
            status: FindingsRepository::STATUS_FLAGGED,
        );
        if ($existing !== null && isset($existing['id'])) {
            return (int) $existing['id'];
        }

        [$topLabel, $topWeight, $categoryList] = $this->summariseSignals($signals);

        return $this->repository->insert([
            'created_at'        => gmdate('Y-m-d H:i:s'),
            'severity'          => $severity->value,
            'status'            => FindingsRepository::STATUS_FLAGGED,
            'original_path'     => $relativeOriginal,
            'quarantine_path'   => null,
            'sha256'            => $hash,
            'top_signal_label'  => $topLabel,
            'top_signal_weight' => $topWeight,
            'signal_categories' => $categoryList,
            'source'            => $source,
        ]);
    }

    /**
     * Permanently delete a quarantined file and mark its row deleted.
     *
     * @return bool True on success; false if the row is missing, the
     *              quarantine file can no longer be located safely, or
     *              the filesystem refuses the operation.
     */
    public function deletePermanently(int $findingId, int $actorId): bool
    {
        $row = $this->repository->findById(id: $findingId);
        if ($row === null) {
            return false;
        }

        if (ProtectedRootPaths::isProtectedOriginal((string) ($row['original_path'] ?? ''))) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Permanent deletion refused for protected WordPress root/core finding',
                context: ['finding_id' => $findingId],
            );
            return false;
        }

        $quarantinePath = (string) ($row['quarantine_path'] ?? '');
        if ($quarantinePath === '') {
            // Nothing on disk to remove — mark the row deleted anyway.
            return $this->repository->updateStatus(
                id: $findingId,
                newStatus: FindingsRepository::STATUS_DELETED,
                actionedBy: $actorId,
            );
        }

        $absolute = $this->resolveQuarantineFile(relative: $quarantinePath);
        if ($absolute === null) {
            return false;
        }

        if (!@unlink($absolute)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Delete permanently failed — could not unlink quarantined file',
                context: ['path' => $absolute, 'finding_id' => $findingId],
            );
            return false;
        }
        $sidecar = $absolute . '.json';
        if (file_exists($sidecar) && !@unlink($sidecar)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Delete permanently warning — sidecar unlink failed',
                context: ['path' => $sidecar, 'finding_id' => $findingId],
            );
        }

        $this->pruneEmptyShard(file: $absolute);

        return $this->repository->updateStatus(
            id: $findingId,
            newStatus: FindingsRepository::STATUS_DELETED,
            actionedBy: $actorId,
        );
    }

    /**
     * Restore a quarantined file to its original path and flag the
     * row as a false positive. Refuses to overwrite an existing file
     * at the original path — user resolves that case manually.
     */
    public function restore(int $findingId, int $actorId): bool
    {
        $row = $this->repository->findById(id: $findingId);
        if ($row === null) {
            return false;
        }

        $quarantinePath = (string) ($row['quarantine_path'] ?? '');
        $originalPath   = (string) ($row['original_path'] ?? '');

        if ($quarantinePath === '' || $originalPath === '') {
            return false;
        }

        $targetAbsolute = $this->resolveRestoreTarget(relative: $originalPath);
        if ($targetAbsolute === null) {
            return false;
        }

        if (file_exists($targetAbsolute) || is_link($targetAbsolute)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Restore refused — a file already exists at the original path',
                context: ['target' => $targetAbsolute],
            );
            return false;
        }

        $quarantineAbsolute = $this->resolveQuarantineFile(relative: $quarantinePath);
        if ($quarantineAbsolute === null) {
            return false;
        }

        // Make sure the parent of the restore target exists (plugin
        // dir may have been removed while the finding sat in queue).
        $parentDir = dirname($targetAbsolute);
        if (!is_dir($parentDir) && !wp_mkdir_p($parentDir)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Restore failed — parent directory unavailable',
                context: ['parent' => $parentDir],
            );
            return false;
        }

        if (!@rename($quarantineAbsolute, $targetAbsolute)) {
            // Fallback copy+unlink.
            if (!@copy($quarantineAbsolute, $targetAbsolute)) {
                return false;
            }
            if (!@unlink($quarantineAbsolute)) {
                if (!ProtectedRootPaths::isProtected($targetAbsolute)) {
                    @unlink($targetAbsolute);
                }
                $this->logService->warning(
                    module: self::MODULE,
                    message: 'Restore failed — copied file but could not remove quarantine copy',
                    context: ['source' => $quarantineAbsolute, 'target' => $targetAbsolute],
                );
                return false;
            }
        }

        // Remove sidecar and prune empty shard dir.
        $sidecar = $quarantineAbsolute . '.json';
        if (file_exists($sidecar) && !@unlink($sidecar)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Restore warning — sidecar unlink failed',
                context: ['path' => $sidecar, 'finding_id' => $findingId],
            );
        }
        $this->pruneEmptyShard(file: $quarantineAbsolute);

        return $this->repository->updateStatus(
            id: $findingId,
            newStatus: FindingsRepository::STATUS_FALSE_POSITIVE,
            actionedBy: $actorId,
        );
    }

    /**
     * Quarantine root (absolute path) or null if WP_CONTENT_DIR unavailable.
     */
    private function quarantineRoot(): ?string
    {
        if (!defined('WP_CONTENT_DIR')) {
            return null;
        }

        return $this->normalisePath(WP_CONTENT_DIR) . 'hmdg-security-pro/quarantine';
    }

    /**
     * Resolve a relative quarantine path to an absolute filesystem
     * path, verifying the result is still inside the quarantine root.
     * Defence-in-depth against path-traversal on DB-stored values.
     */
    private function resolveQuarantineFile(string $relative): ?string
    {
        $root = $this->quarantineRoot();
        if ($root === null) {
            return null;
        }

        $resolvedRoot = realpath($root);
        if ($resolvedRoot === false) {
            return null;
        }

        $candidate = rtrim($resolvedRoot, '/\\') . '/' . ltrim($relative, '/\\');
        $resolvedCandidate = realpath($candidate);

        if ($resolvedCandidate === false || !is_file($resolvedCandidate)) {
            return null;
        }

        $normalisedRoot = $this->normalisePath(rtrim($resolvedRoot, '/\\') . '/');
        $normalisedCandidate = $this->normalisePath($resolvedCandidate);

        if (!str_starts_with($normalisedCandidate, $normalisedRoot)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Quarantine path containment check failed',
                context: ['candidate' => $candidate],
            );
            return null;
        }

        if (ProtectedRootPaths::isProtected($candidate) || ProtectedRootPaths::isProtected($resolvedCandidate)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Quarantine operation refused for protected WordPress root/core target',
                context: ['candidate' => $candidate],
            );
            return null;
        }

        return $resolvedCandidate;
    }

    /**
     * Resolve a DB-stored original path back into ABSPATH safely.
     */
    private function resolveRestoreTarget(string $relative): ?string
    {
        $resolvedAbspath = realpath(ABSPATH);
        if ($resolvedAbspath === false) {
            return null;
        }

        $root = rtrim($resolvedAbspath, '/\\');
        $candidate = $root . '/' . ltrim($relative, '/\\');
        // WordPress also supports wp-config.php immediately above ABSPATH.
        $parentConfig = dirname($root) . '/wp-config.php';
        if (ProtectedRootPaths::normalise($candidate) === ProtectedRootPaths::normalise($parentConfig)) {
            return $parentConfig;
        }
        $parentDir = dirname($candidate);
        $resolvedParent = realpath($parentDir);

        if ($resolvedParent === false) {
            $existingAncestor = $this->nearestExistingAncestor(path: $parentDir);
            if ($existingAncestor === null) {
                $this->logService->warning(
                    module: self::MODULE,
                    message: 'Restore refused — parent path does not resolve inside ABSPATH',
                    context: ['target' => $candidate],
                );
                return null;
            }
            $resolvedParent = $existingAncestor;
        }

        $normalisedRoot = $this->normalisePath($root . '/');
        $normalisedParent = $this->normalisePath(rtrim($resolvedParent, '/\\') . '/');

        if (!str_starts_with($normalisedParent, $normalisedRoot)) {
            $this->logService->warning(
                module: self::MODULE,
                message: 'Restore containment check failed',
                context: ['target' => $candidate],
            );
            return null;
        }

        return $candidate;
    }

    private function nearestExistingAncestor(string $path): ?string
    {
        $cursor = $path;

        while ($cursor !== '' && $cursor !== '.' && $cursor !== dirname($cursor)) {
            if (file_exists($cursor)) {
                $resolved = realpath($cursor);
                return $resolved === false ? null : $resolved;
            }

            $cursor = dirname($cursor);
        }

        return null;
    }

    /**
     * Remove an empty shard directory (and date directory if that
     * also ends up empty) to keep the quarantine tree tidy.
     */
    private function pruneEmptyShard(string $file): void
    {
        $shardDir = dirname($file);
        $dateDir  = dirname($shardDir);
        $root     = $this->quarantineRoot();

        if ($root === null) {
            return;
        }

        $normalisedRoot = $this->normalisePath(rtrim($root, '/\\') . '/');

        foreach ([$shardDir, $dateDir] as $dir) {
            $normalised = $this->normalisePath($dir);
            if (!str_starts_with($normalised, $normalisedRoot)) {
                return;
            }
            if ($this->isEmptyDirectory(dir: $dir)) {
                @rmdir($dir);
            } else {
                return;
            }
        }
    }

    private function isEmptyDirectory(string $dir): bool
    {
        if (!is_dir($dir)) {
            return false;
        }
        $items = @scandir($dir);
        if (!is_array($items)) {
            return false;
        }
        foreach ($items as $item) {
            if ($item !== '.' && $item !== '..') {
                return false;
            }
        }
        return true;
    }

    /**
     * Normalise a filesystem path to forward slashes and guarantee a
     * trailing slash for directory-style inputs.
     */
    private function normalisePath(string $path): string
    {
        $normalised = str_replace('\\', '/', $path);
        $isDir = is_dir($path) || str_ends_with($path, '/') || str_ends_with($path, '\\');

        return $isDir ? rtrim($normalised, '/') . '/' : $normalised;
    }

    /**
     * Produce the quarantine-root-relative path used in DB rows.
     */
    private function relativeFromContent(string $path): string
    {
        $root = $this->quarantineRoot();
        if ($root === null) {
            return '';
        }

        $normalisedRoot = $this->normalisePath(rtrim($root, '/\\') . '/');
        $normalisedPath = $this->normalisePath($path);

        if (str_starts_with($normalisedPath, $normalisedRoot)) {
            return substr($normalisedPath, strlen($normalisedRoot));
        }

        return $normalisedPath;
    }

    /**
     * Pick the top signal (highest weight) and build a categories csv.
     *
     * @param list<Signal> $signals
     * @return array{0: ?string, 1: ?int, 2: ?string}
     */
    private function summariseSignals(array $signals): array
    {
        $top = null;
        $categories = [];

        foreach ($signals as $signal) {
            if (!$signal instanceof Signal) {
                continue;
            }
            $categories[$signal->category->value] = true;
            if ($top === null || $signal->weight > $top->weight) {
                $top = $signal;
            }
        }

        return [
            $top?->label,
            $top?->weight,
            $categories === [] ? null : implode(',', array_keys($categories)),
        ];
    }
}
