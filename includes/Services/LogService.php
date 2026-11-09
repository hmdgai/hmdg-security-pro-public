<?php

declare(strict_types=1);

namespace HMDG\Security\Services;

/**
 * File-based security logger. Never writes to the database.
 *
 * All entries are appended to a single log file under
 * WP_CONTENT_DIR/hmdg-security-pro/security.log. Automatic rotation keeps
 * disk usage in check: when the file exceeds 5 MB the current log is
 * shifted through up to three numbered backups (.1, .2, .3).
 *
 * Every log line includes the active page-builder context so that
 * debugging builder-related incidents does not require cross-referencing
 * separate logs. Sensitive values (passwords, tokens, card numbers) are
 * stripped before writing.
 *
 * Format: [TIMESTAMP] [SEVERITY] [MODULE] Message | Context JSON
 *
 * @since 1.0.0
 */
final class LogService
{
    /**
     * Maximum log file size in bytes before rotation (5 MB).
     */
    private const MAX_FILE_SIZE = 5 * 1024 * 1024;

    /**
     * Maximum number of rotated backup files to retain.
     */
    private const MAX_ROTATED_FILES = 3;

    /**
     * Keys whose values must never appear in log output.
     *
     * @var list<string>
     */
    private const SENSITIVE_KEYS = [
        'password',
        'token',
        'secret',
        'card_number',
        'credit_card',
        'authorization',
    ];

    /**
     * Absolute path to the security log file.
     */
    private readonly string $logPath;

    /**
     * Absolute path to the log directory.
     */
    private readonly string $logDir;

    /**
     * Per-request cache: have we verified the directory exists yet?
     *
     * Without this flag, every log call invokes is_dir() (and potentially
     * wp_mkdir_p() + an atomic write for .htaccess). Once is enough.
     */
    private bool $directoryChecked = false;

    /**
     * Per-request cache: have we run the rotation check yet?
     *
     * Without this flag, every log call calls file_exists() + filesize().
     * The log can only be rotated once per request, so check once.
     */
    private bool $rotationChecked = false;

    /**
     * @param BuilderDetectionService $builderDetection Builder detection for enriching log context.
     */
    public function __construct(
        private readonly BuilderDetectionService $builderDetection,
    ) {
        $this->logDir = WP_CONTENT_DIR . '/hmdg-security-pro';
        $this->logPath = $this->logDir . '/security.log';
    }

    /**
     * Write a log entry at the given severity level.
     *
     * Sensitive keys are stripped from the context array, builder state
     * is appended, and the log file is rotated if it exceeds the size
     * threshold before the new entry is written.
     *
     * @param string               $severity One of 'CRITICAL', 'WARNING', 'INFO'.
     * @param string               $module   Module identifier (e.g. 'LoginProtection').
     * @param string               $message  Human-readable log message.
     * @param array<string, mixed> $context  Optional structured context data.
     */
    public function log(string $severity, string $module, string $message, array $context = []): void
    {
        // A rejected log target must not attempt to log its own refusal.
        if (!ProtectedRootPaths::allowsWrite($this->logPath)
            || !ProtectedRootPaths::allowsWrite($this->logDir)) {
            return;
        }
        // Cached per-request: avoid redundant filesystem checks on every call
        if (!$this->directoryChecked) {
            $this->ensureDirectoryExists();
            $this->directoryChecked = true;
        }
        if (!$this->rotationChecked) {
            $this->rotateIfNeeded();
            $this->rotationChecked = true;
        }

        $context = $this->sanitizeContext(context: $context);
        $context['active_builders'] = $this->builderDetection->getActiveBuilders();

        $timestamp = (new \DateTimeImmutable(
            datetime: 'now',
            timezone: new \DateTimeZone(timezone: 'Europe/London'),
        ))->format(format: 'Y-m-d H:i:s');

        $contextJson = json_encode(value: $context, flags: JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        // Strip CR/LF/null/control characters from message + module to prevent
        // log-line injection. Today $message comes only from hardcoded strings,
        // but defending at the boundary protects against future regressions.
        $safeMessage = preg_replace('/[\x00-\x1F\x7F]/u', ' ', $message) ?? $message;
        $safeModule = preg_replace('/[\x00-\x1F\x7F]/u', ' ', $module) ?? $module;

        $line = sprintf(
            "[%s] [%s] [%s] %s | %s\n",
            $timestamp,
            strtoupper($severity),
            $safeModule,
            $safeMessage,
            $contextJson,
        );

        SafeFileWriter::append($this->logPath, $line);
    }

    /**
     * Log an informational message.
     *
     * @param string               $module  Module identifier.
     * @param string               $message Human-readable log message.
     * @param array<string, mixed> $context Optional structured context data.
     */
    public function info(string $module, string $message, array $context = []): void
    {
        $this->log(severity: 'INFO', module: $module, message: $message, context: $context);
    }

    /**
     * Log a warning message.
     *
     * @param string               $module  Module identifier.
     * @param string               $message Human-readable log message.
     * @param array<string, mixed> $context Optional structured context data.
     */
    public function warning(string $module, string $message, array $context = []): void
    {
        $this->log(severity: 'WARNING', module: $module, message: $message, context: $context);
    }

    /**
     * Log a critical message.
     *
     * @param string               $module  Module identifier.
     * @param string               $message Human-readable log message.
     * @param array<string, mixed> $context Optional structured context data.
     */
    public function critical(string $module, string $message, array $context = []): void
    {
        $this->log(severity: 'CRITICAL', module: $module, message: $message, context: $context);
    }

    /**
     * Rotate the log file when it exceeds the maximum size.
     *
     * Existing rotated files are shifted up by one (e.g. .2 becomes .3,
     * .1 becomes .2) and the current log is renamed to .1. The oldest
     * rotated file beyond the retention limit is silently discarded.
     */
    private function rotateIfNeeded(): void
    {
        if (!file_exists($this->logPath)) {
            return;
        }

        $size = filesize($this->logPath);

        if ($size === false || $size < self::MAX_FILE_SIZE) {
            return;
        }

        // Shift existing rotated files upward: .2 -> .3, .1 -> .2, current -> .1
        for ($i = self::MAX_ROTATED_FILES; $i >= 1; $i--) {
            $source = $i > 1
                ? $this->logPath . '.' . ($i - 1)
                : $this->logPath;
            $target = $this->logPath . '.' . $i;

            if (ProtectedRootPaths::allowsWrite($source)
                && ProtectedRootPaths::allowsWrite($target) && file_exists($source)) {
                // If target already exists (e.g. the oldest), it will be overwritten
                rename(from: $source, to: $target);
            }
        }
    }

    /**
     * Remove sensitive key-value pairs from the context array.
     *
     * Recursively walks the array and replaces any key matching a known
     * sensitive name with the placeholder '[REDACTED]'.
     *
     * @param array<string, mixed> $context Raw context data.
     *
     * @return array<string, mixed> Sanitized context data.
     */
    private function sanitizeContext(array $context): array
    {
        $sanitized = [];

        foreach ($context as $key => $value) {
            $lowerKey = strtolower((string) $key);

            if (in_array($lowerKey, self::SENSITIVE_KEYS, true)) {
                $sanitized[$key] = '[REDACTED]';
                continue;
            }

            if (is_array($value)) {
                $sanitized[$key] = $this->sanitizeContext(context: $value);
                continue;
            }

            $sanitized[$key] = $value;
        }

        return $sanitized;
    }

    /**
     * Ensure the log directory exists with appropriate permissions.
     */
    private function ensureDirectoryExists(): void
    {
        if (!ProtectedRootPaths::allowsWrite($this->logDir)) {
            return;
        }
        if (is_dir($this->logDir)) {
            return;
        }

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir
        wp_mkdir_p(target: $this->logDir);

        // Write an .htaccess to prevent direct web access to log files
        $htaccessPath = $this->logDir . '/.htaccess';

        if (ProtectedRootPaths::allowsWrite($htaccessPath) && !file_exists($htaccessPath)) {
            SafeFileWriter::replace($htaccessPath, "Deny from all\n");
        }
    }
}
