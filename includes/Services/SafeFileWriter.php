<?php

declare(strict_types=1);

namespace HMDG\Security\Services;

/**
 * Guarded file writes that never wait for an advisory filesystem lock.
 *
 * Replacement is atomic on the same filesystem, with last-writer-wins semantics.
 * Log appends are best effort: one bounded write, with no lock or retry.
 *
 * @package HMDG\Security
 * @since 1.11.3
 */
final class SafeFileWriter
{
    private const MAX_APPEND_BYTES = 65536;

    /**
     * Replace only after every byte is written to a same-directory temporary file.
     *
     * @param string $path Destination outside protected WordPress paths.
     * @param string $contents Complete replacement contents.
     * @return bool Failure retains the previous destination and removes only our temp file.
     */
    public static function replace(string $path, string $contents): bool
    {
        $directory = dirname($path);
        if (!ProtectedRootPaths::allowsWrite($path) || !ProtectedRootPaths::allowsWrite($directory)
            || !is_dir($directory)) {
            return false;
        }
        $temporary = $directory . '/.hmdg-write-' . bin2hex(random_bytes(16)) . '.tmp';
        if (!ProtectedRootPaths::allowsWrite($temporary)) {
            return false;
        }
        $stream = fopen($temporary, 'xb');
        if ($stream === false) {
            return false;
        }
        try {
            // Keep unpublished bytes private even when the original destination is 0600.
            if (!ProtectedRootPaths::allowsWrite($temporary) || !chmod($temporary, 0600)) {
                return false;
            }
            $complete = self::writeComplete($stream, $contents) && fflush($stream);
            $closed = fclose($stream);
            $stream = null;
            if (!$complete || !$closed) {
                return false;
            }
            $permissions = is_file($path) ? fileperms($path) : (defined('FS_CHMOD_FILE') ? FS_CHMOD_FILE : 0644);
            if ($permissions === false || !ProtectedRootPaths::allowsWrite($temporary)
                || !chmod($temporary, $permissions & 0777) || !ProtectedRootPaths::allowsWrite($path)) {
                return false;
            }
            // Never unlink the destination to make a failed rename succeed.
            return rename($temporary, $path);
        } finally {
            if (is_resource($stream)) {
                fclose($stream);
            }
            if (is_file($temporary) && ProtectedRootPaths::allowsWrite($temporary)) {
                unlink($temporary);
            }
        }
    }

    /**
     * Append a complete bounded log line without locking or retrying a short write.
     *
     * @param string $path Log outside protected WordPress paths.
     * @param string $line Already formatted log line; oversized entries are dropped intact.
     * @return bool Whether one write accepted the entire line.
     */
    public static function append(string $path, string $line): bool
    {
        $length = strlen($line);
        if ($length === 0 || $length > self::MAX_APPEND_BYTES || !ProtectedRootPaths::allowsWrite($path)
            || !ProtectedRootPaths::allowsWrite(dirname($path))) {
            return false;
        }
        $stream = fopen($path, 'ab');
        if ($stream === false) {
            return false;
        }
        try {
            return fwrite($stream, $line) === $length;
        } finally {
            fclose($stream);
        }
    }

    /** @param resource $stream @return bool False on a failed or non-progressing write. */
    private static function writeComplete($stream, string $contents): bool
    {
        $offset = 0;
        $length = strlen($contents);
        while ($offset < $length) {
            $written = fwrite($stream, substr($contents, $offset, 65536));
            if ($written === false || $written === 0) {
                return false;
            }
            $offset += $written;
        }
        return true;
    }
}
