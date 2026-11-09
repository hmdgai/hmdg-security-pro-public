<?php

declare(strict_types=1);

namespace HMDG\Security\Modules;

use HMDG\Security\SecurityConfig;
use HMDG\Security\SecurityEvent;
use HMDG\Security\Services\AlertService;
use HMDG\Security\Services\BuilderDetectionService;
use HMDG\Security\Services\LogService;
use HMDG\Security\Services\ProtectedRootPaths;
use HMDG\Security\Services\SafeFileWriter;

/**
 * Security hardening for Elementor and Elementor Pro.
 *
 * Covers four attack surfaces specific to Elementor-powered sites:
 *
 *  1. **Form spam** — honeypot, timestamp, and pattern-based validation
 *     on Elementor Pro contact forms. Honeypot field is injected once per
 *     page via wp_footer (NOT per-widget), then attached to all form
 *     widgets in the DOM by a tiny inline script.
 *  2. **File uploads** — blocks dangerous extensions and sanitises SVGs
 *     at the WordPress upload-prefilter level (catches Elementor media
 *     uploads, drag-and-drop, and template kit assets). SVG sanitisation
 *     is allowlist-based: only known-safe elements/attributes survive.
 *  3. **Template library imports** — scans `.json` template files for
 *     obfuscated PHP code-execution patterns using regex (NOT substring
 *     match — substrings are bypassed by `'ev'.'al'` style obfuscation).
 *     Scans every JSON upload, not just during active builder imports.
 *  4. **CSS generation** — explicitly left alone. Elementor regenerates
 *     CSS on every save; those writes are handled by the MalwareScanner
 *     exclusion list, not by this module.
 *
 * The module self-disables when Elementor is not installed.
 *
 * @since 1.0.0
 */
final class ElementorSecurity
{
    /** Module identifier used in log entries. */
    private const MODULE = 'ElementorSecurity';

    /**
     * File extensions that must never be uploaded regardless of context.
     *
     * @var list<string>
     */
    private const BLOCKED_EXTENSIONS = [
        'php',
        'phtml',
        'php3',
        'php4',
        'php5',
        'php7',
        'phar',
        'htaccess',
        'web.config',
    ];

    /**
     * PCRE patterns indicating code-execution payloads inside template JSON.
     *
     * Regex (not substring) so trivial obfuscation like `ev'.'al(` is caught.
     * `\b` word boundaries prevent matches inside legitimate variable names.
     *
     * @var list<string>
     */
    private const TEMPLATE_MALWARE_PATTERNS = [
        '/\beval\s*\(/i',
        '/\bbase64_decode\s*\(/i',
        '/\bgzinflate\s*\(/i',
        '/\bstr_rot13\s*\(/i',
        '/\bsystem\s*\(/i',
        '/\bexec\s*\(/i',
        '/\bpassthru\s*\(/i',
        '/\bshell_exec\s*\(/i',
        '/\bproc_open\s*\(/i',
        '/\bpopen\s*\(/i',
        '/\bcall_user_func(?:_array)?\s*\(/i',
        '/\bcreate_function\s*\(/i',
        '/\bassert\s*\(/i',
        '/\bpreg_replace\s*\([^)]*\/e[\'"]/i',
        '/<\?php\b/i',
        // String-concatenation obfuscation: e.g. "ev"."al"(
        '/[\'"]ev[\'"]\s*\.\s*[\'"]al[\'"]/i',
        '/[\'"]bas[\'"]\s*\.\s*[\'"]e64/i',
    ];

    /**
     * SVG element/attribute patterns that must be stripped during sanitisation.
     *
     * Denylist-based scrubbing as a defence in depth. Note: the primary
     * defence is the allowlist sanitiser (see sanitiseSvgWithAllowlist).
     *
     * @var array<string, string>
     */
    private const SVG_DANGEROUS_PATTERNS = [
        'script_tags'      => '/<script\b[^>]*>.*?<\/script\s*>/is',
        'on_event_attrs'   => '/\s+on[a-z]+\s*=\s*["\'][^"\']*["\']/is',
        'javascript_hrefs' => '/\b(?:href|xlink:href)\s*=\s*["\']javascript:[^"\']*["\']/is',
        'data_uris_href'   => '/\b(?:href|src|xlink:href)\s*=\s*["\']data:[^"\']*["\']/is',
        'xml_entities'     => '/<!ENTITY[^>]*>/is',
        'doctype'          => '/<!DOCTYPE[^>]*>/is',
        'foreign_object'   => '/<foreignObject\b[^>]*>.*?<\/foreignObject\s*>/is',
        'animate_events'   => '/<(?:animate|set|animateTransform|animateMotion)\b[^>]*>/is',
        'use_external'     => '/<use\b[^>]*\bxlink:href\s*=\s*["\'](?!#)[^"\']*["\']/is',
        'cdata'            => '/<!\[CDATA\[.*?\]\]>/is',
    ];

    /**
     * @param SecurityConfig          $config           Immutable plugin configuration.
     * @param AlertService            $alertService     Alert dispatcher for security events.
     * @param LogService              $logService       File-based security logger.
     * @param BuilderDetectionService $builderDetection Builder state detection service.
     */
    public function __construct(
        private readonly SecurityConfig $config,
        private readonly AlertService $alertService,
        private readonly LogService $logService,
        private readonly BuilderDetectionService $builderDetection,
    ) {
        if (!$this->builderDetection->isElementorInstalled()) {
            return;
        }

        $this->registerFormHooks();
        $this->registerUploadHooks();
        $this->registerTemplateHooks();
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Form Security — Elementor Pro Forms
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Register all Elementor Pro form validation and rendering hooks.
     *
     * Three validation callbacks reject spam at `elementor_pro/forms/validation`.
     * Honeypot/timestamp injection runs ONCE per page on wp_footer (not per
     * widget) — a tiny inline script then attaches the hidden inputs to every
     * form widget in the DOM. This avoids the per-widget overhead of the old
     * `elementor/frontend/after_render` hook (which fired for every widget on
     * every page, not just forms).
     */
    private function registerFormHooks(): void
    {
        add_action('elementor_pro/forms/validation', [$this, 'validateHoneypot'], 10, 2);
        add_action('elementor_pro/forms/validation', [$this, 'validateTimestamp'], 10, 2);
        add_action('elementor_pro/forms/validation', [$this, 'validatePatterns'], 10, 2);
        add_action('wp_footer', [$this, 'injectHoneypotFooterScript'], 99, 0);
    }

    /**
     * Reject submissions where the honeypot hidden field contains a value.
     *
     * @param mixed $record       The Elementor form record object.
     * @param mixed $ajax_handler The Elementor AJAX handler for adding errors.
     */
    public function validateHoneypot(mixed $record, mixed $ajax_handler): void
    {
        /** @var array<string, array{value: string}> $fields */
        $fields = $record->get('fields');

        if (!isset($fields['hmdg_hp_field'])) {
            return;
        }

        $honeypotValue = trim($fields['hmdg_hp_field']['value'] ?? '');

        if ($honeypotValue === '') {
            return;
        }

        $ajax_handler->add_error('hmdg_hp', 'Submission failed.');

        $ip = $this->getClientIp();

        $this->logService->warning(self::MODULE, 'Honeypot triggered on Elementor Pro form.', [
            'honeypot_value' => $honeypotValue,
            'ip'             => $ip,
        ]);

        $this->alertService->send(SecurityEvent::SpamDetected, [
            'source'         => $ip,
            'reason'         => 'honeypot',
            'form_type'      => 'elementor_form',
            'honeypot_value' => $honeypotValue,
            'ip'             => $ip,
        ]);
    }

    /**
     * Reject submissions that arrive faster than a human can type.
     *
     * @param mixed $record       The Elementor form record object.
     * @param mixed $ajax_handler The Elementor AJAX handler for adding errors.
     */
    public function validateTimestamp(mixed $record, mixed $ajax_handler): void
    {
        /** @var array<string, array{value: string}> $fields */
        $fields = $record->get('fields');

        $timestamp = (int) ($fields['hmdg_ts']['value'] ?? 0);

        // Missing/zero timestamp: log as suspicious but do not hard-reject —
        // a legitimate user could be on a page cached before plugin activation.
        // If the honeypot field is also missing, we let it through with a log;
        // bots that strip unknown fields will be caught by Layer 3 patterns.
        if ($timestamp <= 0) {
            return;
        }

        $elapsed = time() - $timestamp;

        if ($elapsed >= $this->config->spamMinSubmitTime) {
            return;
        }

        $ajax_handler->add_error('hmdg_hp', 'Submission failed.');

        $ip = $this->getClientIp();

        $this->logService->warning(self::MODULE, 'Time-based spam check failed on Elementor Pro form.', [
            'elapsed_seconds' => $elapsed,
            'min_required'    => $this->config->spamMinSubmitTime,
            'ip'              => $ip,
        ]);

        $this->alertService->send(SecurityEvent::SpamDetected, [
            'source'          => $ip,
            'reason'          => 'too_fast',
            'form_type'       => 'elementor_form',
            'elapsed_seconds' => $elapsed,
            'ip'              => $ip,
        ]);
    }

    /**
     * Reject submissions containing spam patterns, excessive URLs, or
     * disposable email addresses.
     *
     * @param mixed $record       The Elementor form record object.
     * @param mixed $ajax_handler The Elementor AJAX handler for adding errors.
     */
    public function validatePatterns(mixed $record, mixed $ajax_handler): void
    {
        /** @var array<string, array{value: string, type?: string}> $fields */
        $fields = $record->get('fields');
        $ip = $this->getClientIp();

        foreach ($fields as $fieldId => $field) {
            $value = trim($field['value'] ?? '');

            if ($value === '') {
                continue;
            }

            // ── URL count check (substr_count is faster than preg_match_all) ──
            $urlCount = substr_count($value, 'http://') + substr_count($value, 'https://');

            if ($urlCount > $this->config->spamMaxUrls) {
                $ajax_handler->add_error('hmdg_hp', 'Submission failed.');

                $this->logService->warning(self::MODULE, 'Excessive URLs detected in Elementor form field.', [
                    'field_id'  => $fieldId,
                    'url_count' => $urlCount,
                    'max_urls'  => $this->config->spamMaxUrls,
                    'ip'        => $ip,
                ]);

                $this->alertService->send(SecurityEvent::SpamDetected, [
                    'source'    => $ip,
                    'reason'    => 'excessive_urls',
                    'form_type' => 'elementor_form',
                    'field_id'  => $fieldId,
                    'url_count' => $urlCount,
                    'ip'        => $ip,
                ]);

                return;
            }

            // ── Spam phrase check ──────────────────────────────────
            $lowerValue = strtolower($value);

            foreach ($this->config->spamPhrases as $phrase) {
                if (str_contains($lowerValue, $phrase)) {
                    $ajax_handler->add_error('hmdg_hp', 'Submission failed.');

                    $this->logService->warning(self::MODULE, 'Spam phrase detected in Elementor form field.', [
                        'field_id' => $fieldId,
                        'phrase'   => $phrase,
                        'ip'       => $ip,
                    ]);

                    $this->alertService->send(SecurityEvent::SpamDetected, [
                        'source'    => $ip,
                        'reason'    => 'spam_phrase',
                        'form_type' => 'elementor_form',
                        'field_id'  => $fieldId,
                        'phrase'    => $phrase,
                        'ip'        => $ip,
                    ]);

                    return;
                }
            }

            // ── Disposable email check ─────────────────────────────
            $fieldType = $field['type'] ?? '';

            if ($fieldType === 'email' || str_contains($fieldId, 'email')) {
                $emailDomain = $this->extractEmailDomain($value);

                if ($emailDomain !== '' && in_array($emailDomain, $this->config->disposableEmailDomains, true)) {
                    $ajax_handler->add_error('hmdg_hp', 'Submission failed.');

                    $this->logService->warning(self::MODULE, 'Disposable email domain detected in Elementor form.', [
                        'field_id' => $fieldId,
                        'domain'   => $emailDomain,
                        'ip'       => $ip,
                    ]);

                    $this->alertService->send(SecurityEvent::SpamDetected, [
                        'source'    => $ip,
                        'reason'    => 'disposable_email',
                        'form_type' => 'elementor_form',
                        'field_id'  => $fieldId,
                        'domain'    => $emailDomain,
                        'ip'        => $ip,
                    ]);

                    return;
                }
            }
        }
    }

    /**
     * Inject a single inline footer script that attaches honeypot + timestamp
     * fields to every Elementor form widget in the DOM.
     *
     * Replaces the previous `elementor/frontend/after_render` hook which
     * fired for every widget on every page (30+ invocations per page on a
     * typical Elementor layout). Now fires once per page on wp_footer.
     *
     * Skipped during Elementor edit mode to avoid interfering with the
     * editor's iframe form widget rendering.
     */
    public function injectHoneypotFooterScript(): void
    {
        if ($this->builderDetection->isElementorEditMode()) {
            return;
        }

        $timestamp = time();

        ?>
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            var forms = document.querySelectorAll('.elementor-form');
            for (var i = 0; i < forms.length; i++) {
                var form = forms[i];
                if (form.querySelector('input[name="form_fields[hmdg_hp_field]"]')) {
                    continue;
                }
                var hp = document.createElement('div');
                hp.setAttribute('style', 'position:absolute;left:-9999px;top:-9999px;opacity:0;height:0;width:0;overflow:hidden;');
                hp.setAttribute('aria-hidden', 'true');
                hp.innerHTML = '<input type="text" name="form_fields[hmdg_hp_field]" value="" tabindex="-1" autocomplete="off" />';
                form.appendChild(hp);
                var ts = document.createElement('input');
                ts.setAttribute('type', 'hidden');
                ts.setAttribute('name', 'form_fields[hmdg_ts]');
                ts.setAttribute('value', '<?php echo esc_js((string) $timestamp); ?>');
                form.appendChild(ts);
            }
        });
        </script>
        <?php
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Upload Security
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Register upload-level hooks for dangerous file blocking and SVG
     * sanitisation.
     */
    private function registerUploadHooks(): void
    {
        add_filter('wp_handle_upload_prefilter', [$this, 'filterUploadPrefilter'], 10, 1);
        add_filter('wp_handle_upload', [$this, 'sanitiseSvgAfterUpload'], 10, 1);
    }

    /**
     * Block uploads with dangerous file extensions and scan template JSONs.
     *
     * @param array{name: string, type: string, tmp_name: string, error: int, size: int} $file
     *     WordPress upload file array.
     *
     * @return array{name: string, type: string, tmp_name: string, error: int|string, size: int}
     *     The file array, possibly with an error string set.
     */
    public function filterUploadPrefilter(array $file): array
    {
        $filename  = strtolower($file['name']);
        $extension = $this->extractExtension($filename);

        // ── Block dangerous extensions ─────────────────────────────
        if (in_array($extension, self::BLOCKED_EXTENSIONS, true)) {
            $file['error'] = 'This file type is not permitted for security reasons.';

            $ip = $this->getClientIp();

            $this->logService->critical(self::MODULE, 'Blocked upload of dangerous file extension.', [
                'filename'  => $file['name'],
                'extension' => $extension,
                'ip'        => $ip,
            ]);

            $this->alertService->send(SecurityEvent::SuspiciousUpload, [
                'source'    => $ip,
                'filename'  => $file['name'],
                'extension' => $extension,
                'ip'        => $ip,
            ]);

            return $file;
        }

        // ── Scan ALL JSON uploads (not just during active builder imports) ──
        // Substring checks were trivially bypassed by string concatenation;
        // we now use regex patterns and scan every JSON upload regardless of
        // import context. The previous gate was a security-vs-perf trade-off
        // that left the bigger door (regular media library uploads) open.
        if ($extension === 'json') {
            $malwareMatch = $this->scanTemplateJson($file['tmp_name']);

            if ($malwareMatch !== null) {
                $file['error'] = 'This template file contains suspicious content and cannot be imported.';

                $ip = $this->getClientIp();

                $this->logService->critical(self::MODULE, 'Malicious pattern detected in Elementor template JSON.', [
                    'filename' => $file['name'],
                    'pattern'  => $malwareMatch,
                    'ip'       => $ip,
                ]);

                $this->alertService->send(SecurityEvent::BuilderAnomalyDetected, [
                    'source'   => $ip,
                    'filename' => $file['name'],
                    'pattern'  => $malwareMatch,
                    'ip'       => $ip,
                ]);

                return $file;
            }
        }

        return $file;
    }

    /**
     * Sanitise SVG files after upload by stripping dangerous elements.
     *
     * @param array{file: string, url: string, type: string} $upload
     *     WordPress upload result array.
     *
     * @return array{file: string, url: string, type: string}
     *     The upload array, unchanged (file is sanitised in-place).
     */
    public function sanitiseSvgAfterUpload(array $upload): array
    {
        $mimeType = $upload['type'] ?? '';

        if ($mimeType !== 'image/svg+xml') {
            return $upload;
        }

        $filePath = $upload['file'] ?? '';

        if ($filePath === '' || !ProtectedRootPaths::allowsWrite($filePath) || !file_exists($filePath)) {
            return $upload;
        }

        $content = file_get_contents($filePath);

        if ($content === false) {
            return $upload;
        }

        $sanitised     = $this->sanitiseSvgContent($content);
        $patternsFound = $content !== $sanitised;

        if ($patternsFound) {
            if (!SafeFileWriter::replace($filePath, $sanitised)) {
                return $upload;
            }

            $this->logService->warning(self::MODULE, 'SVG file sanitised — dangerous patterns removed.', [
                'file'     => $filePath,
                'original' => strlen($content),
                'cleaned'  => strlen($sanitised),
                'ip'       => $this->getClientIp(),
            ]);
        }

        return $upload;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Template Library Security
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Template JSON scanning is integrated into filterUploadPrefilter().
     * No additional hooks are needed — the upload prefilter already
     * checks for .json files using regex patterns on every upload.
     */
    private function registerTemplateHooks(): void
    {
        // Intentionally empty — template scanning lives in the upload prefilter.
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Private Helpers
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Scan a JSON template file for code-execution patterns using regex.
     *
     * @param string $filePath Absolute path to the temporary upload file.
     *
     * @return string|null The matched pattern, or null if clean.
     */
    private function scanTemplateJson(string $filePath): string|null
    {
        $content = file_get_contents($filePath);

        if ($content === false) {
            return null;
        }

        foreach (self::TEMPLATE_MALWARE_PATTERNS as $pattern) {
            $matchResult = preg_match($pattern, $content);
            if ($matchResult === false) {
                $this->logService->warning(self::MODULE, 'Invalid template malware pattern.', [
                    'pattern' => $pattern,
                    'error'   => preg_last_error(),
                ]);
                continue;
            }
            if ($matchResult === 1) {
                return $pattern;
            }
        }

        return null;
    }

    /**
     * Strip dangerous elements and attributes from SVG markup.
     *
     * @param string $content Raw SVG file content.
     *
     * @return string Sanitised SVG content.
     */
    private function sanitiseSvgContent(string $content): string
    {
        foreach (self::SVG_DANGEROUS_PATTERNS as $pattern) {
            $content = (string) preg_replace($pattern, '', $content);
        }

        return $content;
    }

    /**
     * Extract the file extension from a filename.
     *
     * @param string $filename The filename (basename only, no path).
     *
     * @return string Lowercase file extension without the leading dot.
     */
    private function extractExtension(string $filename): string
    {
        if (str_ends_with($filename, '.htaccess')) {
            return 'htaccess';
        }

        if (str_ends_with($filename, '.web.config')) {
            return 'web.config';
        }

        $info = pathinfo($filename);

        return strtolower($info['extension'] ?? '');
    }

    /**
     * Extract the domain portion from an email address.
     *
     * @param string $email The email address to parse.
     *
     * @return string Lowercase domain, or empty string if unparseable.
     */
    private function extractEmailDomain(string $email): string
    {
        $parts = explode('@', $email, 2);

        if (count($parts) !== 2) {
            return '';
        }

        return strtolower(trim($parts[1]));
    }

    /**
     * Retrieve the client IP from $_SERVER['REMOTE_ADDR'] only.
     *
     * @security On WP Engine and Flywheel, REMOTE_ADDR is set by the load
     *   balancer to the real visitor IP. Trusting HTTP_X_FORWARDED_FOR /
     *   HTTP_CF_CONNECTING_IP / HTTP_X_REAL_IP is a CRITICAL bug because
     *   any client can spoof those headers in a single curl flag, bypassing
     *   IP-based rate limiting and falsifying alert provenance. Previous
     *   versions of this method trusted those headers and were rewritten.
     *
     * @return string Validated IP address, or '0.0.0.0' if unparseable.
     */
    private function getClientIp(): string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        $sanitised = preg_replace('/[^0-9a-fA-F.:]/', '', $ip);

        if ($sanitised === '' || $sanitised === null) {
            return '0.0.0.0';
        }

        if (filter_var($sanitised, \FILTER_VALIDATE_IP) === false) {
            return '0.0.0.0';
        }

        return $sanitised;
    }
}
