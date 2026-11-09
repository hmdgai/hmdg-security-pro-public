<?php

declare(strict_types=1);

namespace HMDG\Security\Services;

/**
 * Authenticates the exact release bytes before WordPress may unpack them.
 *
 * @package HMDG\Security
 * @since 1.11.0
 */
final class SignedReleasePackage
{
    public const MAX_BYTES = 10485760;
    private const MAX_UNPACKED_BYTES = 20971520;

    /**
     * @param string $package Exact public release asset URL.
     * @param string $publicKey Embedded release-signing public key.
     * @return string|\WP_Error Verified temporary ZIP or a refusal, never installed-plugin paths.
     */
    public static function download(string $package, string $publicKey): string|\WP_Error
    {
        $version = ReleaseMetadata::packageVersion($package);
        if (!ReleaseMetadata::allowedContext() || $version === null) {
            return self::error('invalid_source');
        }
        if (!function_exists('sodium_crypto_sign_verify_detached') || !class_exists(\ZipArchive::class)) {
            return self::error('verification_unavailable');
        }
        if (!function_exists('download_url')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        if (!ProtectedRootPaths::allowsWrite(rtrim(get_temp_dir(), '/\\') . '/hmdg-security-pro-download.tmp')) {
            return self::error('protected_temporary_directory');
        }
        $limit = static function (array $args, string $url) use ($package): array {
            if ($url === $package) {
                $args['limit_response_size'] = self::MAX_BYTES + 1;
            }
            return $args;
        };
        add_filter('http_request_args', $limit, 10, 2);
        try {
            $file = download_url($package, 120);
        } finally {
            remove_filter('http_request_args', $limit, 10);
        }
        if (is_wp_error($file)) {
            return self::error('download_failed');
        }
        return self::verifyDownloaded($file, $package, $publicKey, $version);
    }

    /** @return string|\WP_Error The verified file, or error after removing only the temporary download. */
    private static function verifyDownloaded(string $file, string $package, string $publicKey, string $version): string|\WP_Error
    {
        if (!ProtectedRootPaths::allowsWrite($file)) {
            return self::error('protected_temporary_file');
        }
        $size = is_file($file) && is_readable($file) ? filesize($file) : false;
        if ($size === false || $size < 1 || $size > self::MAX_BYTES) {
            wp_delete_file($file);
            return self::error('package_size');
        }
        $response = wp_safe_remote_get($package . '.sig',
            ['timeout' => 30, 'redirection' => 5, 'limit_response_size' => 1024]);
        $signature = !is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200
            ? wp_remote_retrieve_body($response) : '';
        $bytes = file_get_contents($file);
        if (!is_string($bytes) || !self::verifyBytes($bytes, $signature, $publicKey)
            || !self::validateArchive($file, $version)) {
            wp_delete_file($file);
            return self::error('bad_signature_or_archive');
        }
        return $file;
    }

    /**
     * @param string $bytes Original ZIP bytes.
     * @param string $signature Base64 detached Ed25519 signature.
     * @param string $publicKey Base64 Ed25519 public key.
     * @return bool False for unavailable, malformed or mismatching signatures.
     */
    public static function verifyBytes(string $bytes, string $signature, string $publicKey): bool
    {
        if (!function_exists('sodium_crypto_sign_verify_detached') || strlen($bytes) > self::MAX_BYTES) {
            return false;
        }
        $sig = base64_decode(trim($signature), true);
        $key = base64_decode($publicKey, true);
        if ($bytes === '' || $sig === false || $key === false || strlen($sig) !== 64 || strlen($key) !== 32) {
            return false;
        }
        try {
            return sodium_crypto_sign_verify_detached($sig, $bytes, $key);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * A valid old signed ZIP must not be relabelled as a newer release.
     *
     * @param string $file Signed temporary ZIP; no extraction takes place here.
     * @param string $version Version from the requested exact asset URL.
     * @return bool Exact folder, safe entries and matching header/constant versions.
     */
    public static function validateArchive(string $file, string $version): bool
    {
        if (!class_exists(\ZipArchive::class)) {
            return false;
        }
        $zip = new \ZipArchive();
        if ($zip->open($file, \ZipArchive::RDONLY) !== true) {
            return false;
        }
        try {
            return self::archiveEntriesAllowed($zip) && self::bootstrapVersionMatches($zip, $version);
        } finally {
            $zip->close();
        }
    }

    /** @return bool Reject traversal, symlinks, duplicate entries and oversized archive contents. */
    private static function archiveEntriesAllowed(\ZipArchive $zip): bool
    {
        $seen = [];
        $total = 0;
        if ($zip->numFiles < 1 || $zip->numFiles > 2000) {
            return false;
        }
        for ($index = 0; $index < $zip->numFiles; $index++) {
            $stat = $zip->statIndex($index);
            $name = is_array($stat) ? $stat['name'] : '';
            if (!is_string($name) || isset($seen[$name]) || !self::entryAllowed($name)) {
                return false;
            }
            $seen[$name] = true;
            $total += $stat['size'];
            if (!$zip->getExternalAttributesIndex($index, $system, $attributes)
                || (($attributes >> 16) & 0170000) === 0120000 || $total > self::MAX_UNPACKED_BYTES) {
                return false;
            }
        }
        return true;
    }

    /** @return bool Only the fixed bootstrap and include tree are installable. */
    private static function entryAllowed(string $name): bool
    {
        if (str_contains($name, '..') || str_contains($name, '\\') || str_contains($name, "\0")) {
            return false;
        }
        return $name === 'hmdg-security-pro/' || $name === 'hmdg-security-pro/hmdg-security-pro.php'
            || preg_match('#^hmdg-security-pro/includes/(?:[A-Za-z0-9_-]+/)*(?:[A-Za-z0-9_.-]+\.php)?$#D', $name) === 1;
    }

    /** @return bool Package identity and both declared versions agree with the signed URL. */
    private static function bootstrapVersionMatches(\ZipArchive $zip, string $version): bool
    {
        $bootstrap = $zip->getFromName('hmdg-security-pro/hmdg-security-pro.php', 65536);
        return is_string($bootstrap)
            && preg_match('/^\s*\*\s*Plugin Name:\s*HMDG Security Pro\s*$/m', $bootstrap) === 1
            && preg_match('/^\s*\*\s*Version:\s*([0-9.]+)\s*$/m', $bootstrap, $header) === 1
            && preg_match("/define\\(\\s*'HMDG_SECURITY_VERSION'\\s*,\\s*'([0-9.]+)'\\s*\\)/", $bootstrap, $constant) === 1
            && $header[1] === $version && $constant[1] === $version;
    }

    /** @return \WP_Error Leave the running plugin untouched when authenticity cannot be established. */
    private static function error(string $code): \WP_Error
    {
        return new \WP_Error('hmdg_security_' . $code,
            'HMDG Security Pro: the release could not be authenticated. The installed version has been kept.');
    }
}
