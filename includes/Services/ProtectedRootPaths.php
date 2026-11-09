<?php

declare(strict_types=1);

namespace HMDG\Security\Services;

/**
 * Keeps site bootstrap/root files and WordPress core trees available when a scanner flags them.
 *
 * @package HMDG\Security
 * @since 1.11.2
 * @security Check logical paths as well as resolved aliases before destructive operations.
 */
final class ProtectedRootPaths
{
    /**
     * Refuse writes through root/core aliases, including missing destinations.
     *
     * Resolving the nearest existing ancestor also covers paths whose immediate
     * parent has not yet been created. A dangling final link is never writable.
     *
     * @param string $absolutePath File or directory to create, replace or move.
     * @return bool True only for a destination outside the protected site paths.
     */
    public static function allowsWrite(string $absolutePath): bool
    {
        clearstatcache(true, $absolutePath);
        if (self::isProtected($absolutePath) || is_link($absolutePath)) {
            return false;
        }
        if (is_file($absolutePath)) {
            $stat = lstat($absolutePath);
            // Writing a hard link also edits its other names, which may be core files.
            if ($stat === false || $stat['nlink'] > 1) {
                return false;
            }
        }
        $ancestor = dirname($absolutePath);
        while (!file_exists($ancestor) && !is_link($ancestor)) {
            $parent = dirname($ancestor);
            if ($parent === $ancestor) {
                return false;
            }
            $ancestor = $parent;
        }
        $resolved = realpath($ancestor);
        $path = self::normalise($absolutePath);
        $logicalAncestor = self::normalise($ancestor);
        if ($resolved === false || $path === null || $logicalAncestor === null) {
            return false;
        }
        $projected = rtrim($resolved, '/\\') . substr($path, strlen($logicalAncestor));
        return !self::isProtected($projected);
    }

    /**
     * Includes missing root files and the supported parent wp-config.php location.
     *
     * @param string $absolutePath Source, destination or stored absolute path.
     * @return bool Invalid paths also fail closed.
     */
    public static function isProtected(string $absolutePath): bool
    {
        $candidates = self::candidates($absolutePath);
        $roots = self::roots();
        if ($candidates === [] || $roots === []) {
            return true;
        }
        $aliases = self::rootFileAliases($roots);
        if ($aliases === null) {
            return true;
        }
        $coreDirectories = self::coreDirectories($roots);
        foreach ($candidates as $candidate) {
            foreach ($roots as $root) {
                if ($candidate === $root || dirname($candidate) === $root
                    || $candidate === dirname($root) . '/wp-config.php') {
                    return true;
                }
            }
            if (isset($aliases[$candidate])) {
                return true;
            }
            foreach ($coreDirectories as $directory => $original) {
                if ($candidate === $directory || str_starts_with($candidate, $directory . '/')) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Classify old finding rows even after their original file has been moved.
     *
     * @param string $originalPath ABSPATH-relative original path from a finding.
     * @return bool Missing/invalid original paths cannot authorise destruction.
     */
    public static function isProtectedOriginal(string $originalPath): bool
    {
        if ($originalPath === '' || !defined('ABSPATH')) {
            return true;
        }
        $absolute = self::isAbsolute($originalPath)
            ? $originalPath : rtrim(ABSPATH, '/\\') . '/' . $originalPath;
        return self::isProtected($absolute);
    }

    /**
     * Check root-file aliases once before walking a large plugin tree.
     * @param string $directory Directory considered for recursive removal.
     * @return bool True if removal could include a protected file or core tree.
     */
    public static function containsProtectedPaths(string $directory): bool
    {
        if (self::isProtected($directory)) {
            return true;
        }
        $resolved = realpath($directory);
        $normalised = $resolved !== false ? self::normalise($resolved) : null;
        if ($normalised === null) {
            return true;
        }
        $roots = self::roots();
        $aliases = self::rootFileAliases($roots);
        if ($aliases === null) {
            return true;
        }
        foreach (array_keys($aliases + self::coreDirectories($roots)) as $protected) {
            if ($protected === $normalised || str_starts_with($protected, $normalised . '/')) {
                return true;
            }
        }
        return false;
    }

    /**
     * Preserve the actual root alias in the review queue, including ../wp-config.php.
     *
     * @param string $absolutePath Existing scanned file.
     * @return string|null Safe original path, or null outside the supported site paths.
     */
    public static function originalPath(string $absolutePath): ?string
    {
        $roots = self::roots();
        $aliases = self::rootFileAliases($roots);
        if ($aliases === null) {
            return null;
        }
        $coreDirectories = self::coreDirectories($roots);
        foreach (self::candidates($absolutePath) as $candidate) {
            if (isset($aliases[$candidate])) {
                return $aliases[$candidate];
            }
            foreach ($coreDirectories as $directory => $original) {
                if (str_starts_with($candidate, $directory . '/')) {
                    return $original . substr($candidate, strlen($directory));
                }
            }
            foreach ($roots as $root) {
                if (dirname($candidate) === $root) {
                    return basename($candidate);
                }
                if ($candidate === dirname($root) . '/wp-config.php') {
                    return '../wp-config.php';
                }
            }
        }
        $resolved = realpath($absolutePath);
        $normalised = $resolved !== false ? self::normalise($resolved) : null;
        foreach ($roots as $root) {
            if ($normalised !== null && str_starts_with($normalised, $root . '/')) {
                return substr($normalised, strlen($root) + 1);
            }
        }
        return null;
    }

    /**
     * Canonical comparison form; collapses traversal without requiring the file to exist.
     * @param string $path Absolute filesystem path.
     * @return string|null Normalised comparison form, or null for a relative/invalid path.
     */
    public static function normalise(string $path): ?string
    {
        $path = str_replace('\\', '/', $path);
        if (str_contains($path, "\0") || !self::isAbsolute($path)) {
            return null;
        }
        $prefix = str_starts_with($path, '//') ? '//' : '';
        $parts = [];
        foreach (explode('/', $path) as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..') {
                if ($parts !== [] && !str_ends_with(end($parts), ':')) {
                    array_pop($parts);
                }
                continue;
            }
            $parts[] = $part;
        }
        $normalised = $prefix . implode('/', $parts);
        if (preg_match('/^[A-Za-z]:$/', $normalised)) {
            $normalised .= '/';
        }
        if (!preg_match('/^[A-Za-z]:\//', $normalised) && $prefix === '') {
            $normalised = '/' . $normalised;
        }
        return PHP_OS_FAMILY === 'Windows' ? strtolower($normalised) : $normalised;
    }

    /** @return list<string> Logical and canonical WordPress installation roots. */
    private static function roots(): array
    {
        if (!defined('ABSPATH')) {
            return [];
        }
        return array_values(array_unique(array_filter([
            self::normalise(ABSPATH),
            ($resolved = realpath(ABSPATH)) !== false ? self::normalise($resolved) : null,
        ])));
    }

    /** @return list<string> Include a resolved parent when the final file is already missing. */
    private static function candidates(string $path): array
    {
        $normalised = self::normalise($path);
        if ($normalised === null) {
            return [];
        }
        $resolved = realpath($path);
        $parent = realpath(dirname($path));
        return array_values(array_unique(array_filter([
            $normalised,
            $resolved !== false ? self::normalise($resolved) : null,
            $parent !== false ? self::normalise($parent . '/' . basename($path)) : null,
        ])));
    }

    /** @param list<string> $roots @return array<string, string>|null Resolved aliases, or refusal for an unreadable root. */
    private static function rootFileAliases(array $roots): ?array
    {
        $aliases = [];
        foreach ($roots as $root) {
            $parentConfig = dirname($root) . '/wp-config.php';
            $aliases[$parentConfig] = '../wp-config.php';
            if (($resolved = realpath($parentConfig)) !== false) {
                $aliases[self::normalise($resolved)] = '../wp-config.php';
            }
            try {
                foreach (new \DirectoryIterator($root) as $entry) {
                    if ($entry->isDot() || (!$entry->isFile() && !$entry->isLink())) {
                        continue;
                    }
                    $aliases[self::normalise($entry->getPathname())] = $entry->getFilename();
                    if (($resolved = $entry->getRealPath()) !== false) {
                        $aliases[self::normalise($resolved)] = $entry->getFilename();
                    }
                }
            } catch (\UnexpectedValueException) {
                // Without a complete root listing, destructive callers cannot establish alias safety.
                return null;
            }
        }
        return $aliases;
    }

    /** @param list<string> $roots @return array<string, string> Logical/canonical core trees. */
    private static function coreDirectories(array $roots): array
    {
        $directories = [];
        foreach ($roots as $root) {
            foreach (['wp-admin', defined('WPINC') ? WPINC : 'wp-includes'] as $relative) {
                $directory = self::normalise($root . '/' . $relative);
                if ($directory === null) {
                    continue;
                }
                $directories[$directory] = $relative;
                if (($resolved = realpath($directory)) !== false) {
                    $directories[self::normalise($resolved)] = $relative;
                }
            }
        }
        return $directories;
    }

    private static function isAbsolute(string $path): bool
    {
        $path = str_replace('\\', '/', $path);
        return str_starts_with($path, '/') || preg_match('/^[A-Za-z]:\//', $path) === 1;
    }
}
