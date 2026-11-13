<?php

declare(strict_types=1);

namespace HMDG\Security\Services;

use HMDG\Security\Compatibility\HmdgHelpersCompat;
use HMDG\Security\Detection\Severity;
use HMDG\Security\SecurityConfig;
use HMDG\Security\SecurityEvent;

/**
 * Centralised email alert dispatcher for all security events.
 *
 * Detection modules route alerts through this service. Event policy is
 * checked first; no current event has verified-malware evidence, so all
 * existing detections are email-silent. The retained delivery path enforces
 * rate limiting (one alert per event+source combination per hour),
 * suppresses alerts during builder import
 * operations, and produces clean HTML emails with inline CSS.
 *
 * @since 1.0.0
 */
final class AlertService
{
    /**
     * Global hourly alert cap — prevents email-flood under botnet attacks.
     *
     * Per-event+source rate limiting alone is insufficient: a botnet of N
     * unique IPs can still trigger N separate alert emails per event-type
     * per hour. This cap stops any single hour exceeding GLOBAL_HOURLY_CAP
     * total alert emails across all events combined.
     */
    private const GLOBAL_HOURLY_CAP = 30;

    /** Cache key for the global hourly counter. */
    private const GLOBAL_CAP_KEY = 'alert_global_hourly_count';

    /**
     * Object-cache key prefix for per-unique-key alert dedup markers.
     *
     * Callers pass an optional `unique_key` in the alert context (for
     * example `file_modified:wp-content/plugins/acme/acme.php`). A
     * repeat dispatch for the same unique_key within
     * `UNIQUE_KEY_DEDUP_TTL` is suppressed entirely. Orthogonal to the
     * per-event+source rate limit — the rate limit prevents any given
     * event type from flooding within a short window, whereas this dedup
     * prevents the same file being alerted twice over the course of a
     * week of weekly scans.
     */
    private const UNIQUE_KEY_DEDUP_PREFIX = 'hmdg_alert_sent_';

    /** Dedup TTL — matches the UpdateMonitor grace window. */
    private const UNIQUE_KEY_DEDUP_TTL = 7 * DAY_IN_SECONDS;

    /**
     * @param SecurityConfig          $config           Plugin configuration.
     * @param LogService              $logService       File logger for recording sent alerts.
     * @param BuilderDetectionService $builderDetection Builder state for suppression and context.
     * @param ObjectCacheService      $cacheService     Object cache for rate limiting.
     */
    public function __construct(
        private readonly SecurityConfig $config,
        private readonly LogService $logService,
        private readonly BuilderDetectionService $builderDetection,
        private readonly ObjectCacheService $cacheService,
    ) {}

    /**
     * Dispatch an email alert for a security event.
     *
     * SecurityEvent policy is authoritative and is checked before severity,
     * context, builder state or cache access. No current event is eligible;
     * a severity override or a caller's confirmation claim cannot enable it.
     * Eligible alerts would also be suppressed during a builder import or
     * when the same event+source combination was already alerted within the
     * configured rate-limit window. On success the alert is logged and a
     * rate-limit key is planted in the object cache.
     *
     * v1.4.0 addition: when the caller is the detection engine, an
     * optional `Severity` can be supplied — either as an explicit
     * `$severity` parameter or via `$context['severity_enum']`. When
     * present, the email subject line prefers `Severity::emailSubject()`
     * over the static SecurityEvent::label() so the operator sees the
     * tier-specific phrase ("High Risk Tampering" etc.).
     *
     * @param SecurityEvent        $event    The security event that triggered the alert.
     * @param array<string, mixed> $context  Additional context data for the email body.
     * @param Severity|null        $severity Optional risk-scorer severity for subject override.
     */
    public function send(SecurityEvent $event, array $context = [], ?Severity $severity = null): void
    {
        // Verified-malware-only policy: every existing event is denied.
        // Heuristic severity and the legacy MalwareDetected label do not
        // prove malware. Keep this before all context/severity overrides.
        // Callers retain logging, admin records and quarantine behaviour.
        // Returning silently here is intentional: the event is already
        // logged at the call site, so re-logging the suppression would
        // double the log volume on every login lockout, user creation,
        // spam hit, etc.
        if (!$event->emitsEmail()) {
            return;
        }

        // Back-compat shim: allow callers to pass the severity via the
        // context array as an int matching a Severity case value. This
        // keeps the existing AlertDispatcher call shape (which threads
        // through `severity_enum` in context) working without requiring
        // every caller to switch to the third parameter.
        if ($severity === null && isset($context['severity_enum']) && is_int($context['severity_enum'])) {
            $severity = Severity::tryFrom($context['severity_enum']);
        }

        $isCriticalFinding = $severity?->isCritical() ?? ($event->severity() === 'CRITICAL');

        // 1. Never alert during builder imports
        if ($this->builderDetection->isBuilderImportActive()) {
            $this->logService->info(
                module: 'AlertService',
                message: 'Alert suppressed during builder import',
                context: ['event' => $event->value],
            );

            return;
        }

        // 1b. Per-unique-key dedup — stops repeat alerts for the same
        // file across consecutive weekly scans. Callers (FileIntegrity,
        // MalwareScanner, etc.) pass `unique_key` with a stable string
        // like `file_modified:wp-content/plugins/acme/acme.php`. If the
        // dedup marker is present, suppress entirely. Marker is planted
        // on successful send below with a 7-day TTL.
        $uniqueKey = (string) ($context['unique_key'] ?? '');

        if (!$isCriticalFinding && $uniqueKey !== '') {
            $uniqueCacheKey = self::UNIQUE_KEY_DEDUP_PREFIX . hash('sha256', $uniqueKey);

            if ($this->cacheService->exists(key: $uniqueCacheKey)) {
                $this->logService->info(
                    module: 'AlertService',
                    message: 'Alert deduplicated by unique_key',
                    context: [
                        'event' => $event->value,
                        'unique_key' => $uniqueKey,
                    ],
                );

                return;
            }
        }

        // 2. Per-event+source rate limiting
        $source = (string) ($context['source'] ?? 'unknown');

        if (!$isCriticalFinding && $this->isRateLimited(event: $event, source: $source)) {
            $this->logService->info(
                module: 'AlertService',
                message: 'Alert rate-limited',
                context: ['event' => $event->value, 'source' => $source],
            );

            return;
        }

        // 2b. Global hourly cap — protects against botnet email-floods.
        // Even if every alert is from a unique source, total emails per
        // hour are capped. CRITICAL alerts bypass the cap; everything
        // else is suppressed once the cap is reached.
        $globalCount = (int) ($this->cacheService->get(key: self::GLOBAL_CAP_KEY) ?: 0);
        if ($globalCount >= self::GLOBAL_HOURLY_CAP && !$isCriticalFinding) {
            $this->logService->info(
                module: 'AlertService',
                message: 'Global hourly alert cap reached — alert suppressed',
                context: [
                    'event' => $event->value,
                    'source' => $source,
                    'count' => $globalCount,
                    'cap' => self::GLOBAL_HOURLY_CAP,
                ],
            );

            return;
        }

        // 3. Build and send
        $siteDomain = wp_parse_url(url: home_url(), component: PHP_URL_HOST) ?: 'localhost';
        $fromEmail = 'wordpress@' . $siteDomain;
        $toEmail = $this->config->alertEmail;
        // Prefer the tier-specific subject phrase when the caller
        // supplied a Severity; fall back to the static event label.
        $subjectLabel = $severity !== null ? $severity->emailSubject() : $event->label();
        $subject = sprintf('[HMDG Security Alert] %s — %s', $subjectLabel, home_url());
        $body = $this->buildEmailBody(event: $event, context: $context);

        $headers = [
            'Content-Type: text/html; charset=UTF-8',
            sprintf('From: HMDG Security <%s>', $fromEmail),
        ];

        // 4. Send via wp_mail
        $sent = wp_mail(to: $toEmail, subject: $subject, message: $body, headers: $headers);

        // 5. Log the alert
        $this->logService->log(
            severity: $event->severity(),
            module: 'AlertService',
            message: sprintf('Alert %s: %s', $sent ? 'sent' : 'failed', $event->label()),
            context: [
                'event' => $event->value,
                'source' => $source,
                'recipient' => $toEmail,
                'sent' => $sent,
            ],
        );

        // 6. Set rate limit + bump global counter
        if ($sent) {
            if (!$isCriticalFinding) {
                $this->setRateLimit(event: $event, source: $source);
            }

            // Plant the per-unique-key dedup marker so a subsequent
            // dispatch for the same file/event combination is suppressed
            // for UNIQUE_KEY_DEDUP_TTL (7 days).
            if (!$isCriticalFinding && $uniqueKey !== '') {
                $this->cacheService->set(
                    key: self::UNIQUE_KEY_DEDUP_PREFIX . hash('sha256', $uniqueKey),
                    value: time(),
                    expiration: self::UNIQUE_KEY_DEDUP_TTL,
                );
            }

            // Initialise global counter with TTL on first hit; otherwise
            // increment in-place. Atomic increment in ObjectCacheService
            // handles concurrent-request races.
            if ($globalCount === 0) {
                $this->cacheService->set(
                    key: self::GLOBAL_CAP_KEY,
                    value: 1,
                    expiration: 3600,
                );
            } else {
                $this->cacheService->increment(key: self::GLOBAL_CAP_KEY);
            }
        }
    }

    /**
     * Build the HTML email body for a security alert.
     *
     * Produces a clean, professional email using inline CSS and a simple
     * table layout. Includes severity badge, event details, server info,
     * builder state, and any additional context.
     *
     * @param SecurityEvent        $event   The security event.
     * @param array<string, mixed> $context Additional context data.
     *
     * @return string Complete HTML email body.
     */
    private function buildEmailBody(SecurityEvent $event, array $context): string
    {
        $severity = $event->severity();
        $severityColor = match ($severity) {
            'CRITICAL' => '#dc3545',
            'WARNING' => '#fd7e14',
            'INFO' => '#0d6efd',
            default => '#6c757d',
        };

        $timestamp = (new \DateTimeImmutable(
            datetime: 'now',
            timezone: new \DateTimeZone(timezone: 'Europe/London'),
        ))->format(format: 'd M Y H:i:s T');

        $siteUrl = home_url();
        $serverIp = sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'] ?? 'N/A'));
        $phpVersion = PHP_VERSION;
        $wpVersion = get_bloginfo(show: 'version');
        $activeBuilders = $this->builderDetection->getActiveBuilders();
        $buildersLabel = $activeBuilders !== [] ? implode(separator: ', ', array: $activeBuilders) : 'None';

        $recommendation = (string) ($context['recommendation'] ?? $this->getDefaultRecommendation(event: $event));

        // Build context rows for additional data
        $contextRowsHtml = '';
        $reservedKeys = ['source', 'recommendation', 'file_path', 'line_number', 'code_snippet', 'unique_key', 'severity_enum'];

        foreach ($context as $key => $value) {
            if (in_array($key, $reservedKeys, true)) {
                continue;
            }

            $displayKey = esc_html(ucwords(str_replace('_', ' ', (string) $key)));
            $displayValue = is_array($value) || is_object($value)
                ? esc_html(json_encode(value: $value, flags: JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT))
                : esc_html((string) $value);

            $contextRowsHtml .= <<<ROW
                        <tr>
                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; font-weight: 600; color: #495057; width: 160px; vertical-align: top;">{$displayKey}</td>
                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; color: #212529;">{$displayValue}</td>
                        </tr>
            ROW;
        }

        // Optional file path row
        $filePathHtml = '';

        if (isset($context['file_path']) && $context['file_path'] !== '') {
            $escapedPath = esc_html((string) $context['file_path']);
            $filePathHtml = <<<FILE
                        <tr>
                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; font-weight: 600; color: #495057; width: 160px; vertical-align: top;">File Path</td>
                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; color: #212529; font-family: 'Courier New', Courier, monospace; font-size: 13px;">{$escapedPath}</td>
                        </tr>
            FILE;
        }

        // Optional line number row
        $lineNumberHtml = '';

        if (isset($context['line_number']) && $context['line_number'] !== '') {
            $escapedLine = esc_html((string) $context['line_number']);
            $lineNumberHtml = <<<LINE
                        <tr>
                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; font-weight: 600; color: #495057; width: 160px; vertical-align: top;">Line Number</td>
                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; color: #212529; font-family: 'Courier New', Courier, monospace; font-size: 13px;">{$escapedLine}</td>
                        </tr>
            LINE;
        }

        // Optional code snippet
        $codeSnippetHtml = '';

        if (isset($context['code_snippet']) && $context['code_snippet'] !== '') {
            $escapedCode = esc_html((string) $context['code_snippet']);
            $codeSnippetHtml = <<<CODE
                        <tr>
                            <td colspan="2" style="padding: 8px 12px; border-bottom: 1px solid #e9ecef;">
                                <div style="font-weight: 600; color: #495057; margin-bottom: 6px;">Suspicious Code</div>
                                <code style="display: block; background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 10px; font-family: 'Courier New', Courier, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; color: #212529;">{$escapedCode}</code>
                            </td>
                        </tr>
            CODE;
        }

        // HMDG Helpers coexistence context. Two rows — active (Yes/No) and
        // version — so the operator receiving a security alert can see at a
        // glance whether the sibling plugin is installed on this site and
        // which version is running. Useful when triaging file-integrity or
        // malware alerts: "was HMDG Helpers just updated?" is a common first
        // question. Values are already sanitised by the compat layer.
        $helpersActive  = HmdgHelpersCompat::is_active();
        $helpersVersion = $helpersActive ? HmdgHelpersCompat::get_version() : 'Not installed';
        $helpersLabel   = $helpersActive ? 'Yes' : 'No';

        $escapedSeverity = esc_html($severity);
        $escapedLabel = esc_html($event->label());
        $escapedSiteUrl = esc_html($siteUrl);
        $escapedServerIp = esc_html($serverIp);
        $escapedPhpVersion = esc_html($phpVersion);
        $escapedWpVersion = esc_html($wpVersion);
        $escapedBuilders = esc_html($buildersLabel);
        $escapedHelpersActive  = esc_html($helpersLabel);
        $escapedHelpersVersion = esc_html($helpersVersion);
        $escapedTimestamp = esc_html($timestamp);
        $escapedRecommendation = esc_html($recommendation);

        return <<<HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>HMDG Security Alert</title>
        </head>
        <body style="margin: 0; padding: 0; background-color: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; padding: 24px 0;">
                <tr>
                    <td align="center">
                        <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
                            <!-- Header -->
                            <tr>
                                <td style="background-color: #1a1a2e; padding: 20px 24px;">
                                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                                        <tr>
                                            <td style="color: #ffffff; font-size: 18px; font-weight: 700;">HMDG Security</td>
                                            <td align="right">
                                                <span style="display: inline-block; background-color: {$severityColor}; color: #ffffff; font-size: 12px; font-weight: 700; padding: 4px 12px; border-radius: 12px; text-transform: uppercase; letter-spacing: 0.5px;">{$escapedSeverity}</span>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>

                            <!-- Event Title -->
                            <tr>
                                <td style="padding: 24px 24px 12px 24px;">
                                    <h1 style="margin: 0; font-size: 22px; font-weight: 700; color: #212529;">{$escapedLabel}</h1>
                                    <p style="margin: 6px 0 0 0; font-size: 13px; color: #6c757d;">{$escapedTimestamp}</p>
                                </td>
                            </tr>

                            <!-- Details Table -->
                            <tr>
                                <td style="padding: 12px 24px;">
                                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border: 1px solid #dee2e6; border-radius: 6px; overflow: hidden;">
                                        {$filePathHtml}
                                        {$lineNumberHtml}
                                        {$codeSnippetHtml}
                                        <tr>
                                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; font-weight: 600; color: #495057; width: 160px;">Site URL</td>
                                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; color: #212529;">{$escapedSiteUrl}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; font-weight: 600; color: #495057; width: 160px;">Server IP</td>
                                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; color: #212529;">{$escapedServerIp}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; font-weight: 600; color: #495057; width: 160px;">PHP Version</td>
                                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; color: #212529;">{$escapedPhpVersion}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; font-weight: 600; color: #495057; width: 160px;">WordPress</td>
                                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; color: #212529;">{$escapedWpVersion}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; font-weight: 600; color: #495057; width: 160px;">Page Builders</td>
                                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; color: #212529;">{$escapedBuilders}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; font-weight: 600; color: #495057; width: 160px;">HMDG Helpers</td>
                                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; color: #212529;">{$escapedHelpersActive}</td>
                                        </tr>
                                        <tr>
                                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; font-weight: 600; color: #495057; width: 160px;">HMDG Helpers Version</td>
                                            <td style="padding: 8px 12px; border-bottom: 1px solid #e9ecef; color: #212529;">{$escapedHelpersVersion}</td>
                                        </tr>
                                        {$contextRowsHtml}
                                    </table>
                                </td>
                            </tr>

                            <!-- Recommendation -->
                            <tr>
                                <td style="padding: 12px 24px 24px 24px;">
                                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color: #f8f9fa; border-left: 4px solid {$severityColor}; border-radius: 0 6px 6px 0;">
                                        <tr>
                                            <td style="padding: 14px 16px;">
                                                <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: #6c757d; margin-bottom: 4px; letter-spacing: 0.5px;">Recommended Action</div>
                                                <div style="font-size: 14px; color: #212529; line-height: 1.5;">{$escapedRecommendation}</div>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>

                            <!-- Footer -->
                            <tr>
                                <td style="background-color: #f8f9fa; padding: 16px 24px; border-top: 1px solid #e9ecef;">
                                    <p style="margin: 0; font-size: 12px; color: #6c757d; text-align: center;">
                                        This alert was generated by HMDG Security Plugin. Do not reply to this email.
                                    </p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        HTML;
    }

    /**
     * Return a sensible default recommendation for each event type.
     *
     * @param SecurityEvent $event The security event.
     *
     * @return string Human-readable recommended action.
     */
    private function getDefaultRecommendation(SecurityEvent $event): string
    {
        return match ($event) {
            SecurityEvent::LoginFailed => 'Monitor for repeated attempts. If persistent, consider blocking the source IP at the firewall level.',
            SecurityEvent::LoginLockout => 'The source IP has been temporarily locked out. Review access logs to determine whether this is a brute-force attack or a legitimate user who forgot their credentials.',
            // Kept after SpamProtection removal in 1.3.0 — DiviSecurity and
            // ElementorSecurity still dispatch SpamDetected, so this
            // recommendation is still reached when their builder-level
            // form checks fire.
            SecurityEvent::SpamDetected => 'The submission was blocked automatically. No action needed unless false positives are reported by legitimate users.',
            SecurityEvent::FileModified => 'Verify the file change was intentional. Compare the file against the WordPress.org checksum to rule out tampering.',
            SecurityEvent::MalwareDetected => 'URGENT: Isolate the affected file immediately. Do not delete it until a forensic copy has been taken. Scan the entire server for related infections.',
            SecurityEvent::NewAdminUser => 'Confirm this administrator account was created by an authorised person. If not, remove the account immediately and audit recent changes.',
            SecurityEvent::RoleEscalation => 'URGENT: Verify this role change was authorised. If not, revert the user role immediately and review the audit trail for the responsible action.',
            SecurityEvent::UserDeleted => 'Verify the deletion was intentional. Check whether any content owned by this user needs to be reassigned.',
            SecurityEvent::SuspiciousUpload => 'URGENT: Quarantine the uploaded file. Do not execute or preview it. Scan it with an external malware analysis tool before taking further action.',
            SecurityEvent::BuilderAnomalyDetected => 'Review the flagged page builder operation. If the behaviour is expected (e.g. a template import), no action is needed. Otherwise, investigate for signs of exploitation.',
        };
    }

    /**
     * Check whether an alert for this event+source is rate-limited.
     *
     * @param SecurityEvent $event  The security event.
     * @param string        $source The alert source identifier.
     *
     * @return bool True if the alert should be suppressed.
     */
    private function isRateLimited(SecurityEvent $event, string $source): bool
    {
        $cacheKey = $this->buildRateLimitKey(event: $event, source: $source);

        return $this->cacheService->exists(key: $cacheKey);
    }

    /**
     * Plant a rate-limit key in the object cache.
     *
     * @param SecurityEvent $event  The security event.
     * @param string        $source The alert source identifier.
     */
    private function setRateLimit(SecurityEvent $event, string $source): void
    {
        $cacheKey = $this->buildRateLimitKey(event: $event, source: $source);

        $this->cacheService->set(
            key: $cacheKey,
            value: true,
            expiration: $this->config->alertRateLimitSeconds,
        );
    }

    /**
     * Build the cache key used for alert rate limiting.
     *
     * @param SecurityEvent $event  The security event.
     * @param string        $source The alert source identifier.
     *
     * @return string Cache key in the format "alert_rate_{event}_{source}".
     */
    private function buildRateLimitKey(SecurityEvent $event, string $source): string
    {
        return sprintf('alert_rate_%s_%s', $event->value, $source);
    }
}
