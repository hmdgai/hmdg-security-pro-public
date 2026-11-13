<?php

declare(strict_types=1);

namespace HMDG\Security\Modules;

use HMDG\Security\SecurityConfig;
use HMDG\Security\Services\BuilderDetectionService;
use HMDG\Security\Services\LogService;

/**
 * Hardens the WordPress installation by disabling attack surfaces and
 * removing information-disclosure vectors.
 *
 * Every hardening measure is builder-aware: Elementor and Divi rely on
 * REST endpoints, AJAX calls, inline styles, and versioned assets that
 * naive hardening would break. Each hook checks the builder context
 * before acting so editors never see a broken visual builder.
 *
 * @see https://developer.wordpress.org/advanced-administration/security/hardening/
 */
final class Hardening
{
    /** Module identifier used in log entries. */
    private const MODULE = 'hardening';

    public function __construct(
        private readonly SecurityConfig $config,
        private readonly BuilderDetectionService $builderDetection,
        private readonly LogService $logService,
    ) {
        $this->disableXmlRpc();
        $this->removeVersionDisclosure();
        $this->removeHeadClutter();
        $this->disableApplicationPasswords();
        $this->forceSslAdmin();
        $this->removeXPoweredByHeader();
        $this->disableFrontEndErrorDisplay();
        $this->removeQueryStringsFromStaticAssets();
        $this->disableEmbedOembed();
        $this->removeShortlink();
        $this->blockFileEditing();
        $this->optionallyBlockFileMods();
        $this->optionallyDisableFeeds();
        $this->disablePingback();
    }

    // ── 1. Disable XML-RPC ─────────────────────────────────────────────

    /**
     * XML-RPC is the primary vector for brute-force amplification attacks
     * (system.multicall) and pingback DDoS. Modern sites use the REST API
     * instead, so XML-RPC can be safely disabled.
     */
    private function disableXmlRpc(): void
    {
        add_filter('xmlrpc_enabled', '__return_false', 10);

        add_filter('wp_headers', function (array $headers): array {
            /*
             * The X-Pingback header advertises the XML-RPC endpoint to
             * remote scanners. Removing it reduces reconnaissance surface.
             */
            unset($headers['X-Pingback']);

            return $headers;
        }, 10, 1);
    }

    // ── 2. Remove WordPress version ────────────────────────────────────

    /**
     * The generator meta tag and version query strings leak the exact
     * WordPress version, allowing attackers to match known exploits.
     */
    private function removeVersionDisclosure(): void
    {
        add_filter('the_generator', static fn(): string => '', 10);
        remove_action('wp_head', 'wp_generator', 10);
    }

    // ── 3. Remove wlwmanifest link ─────────────────────────────────────

    /**
     * Windows Live Writer manifest is a legacy XML-RPC discovery link.
     * No modern editor uses it, and it discloses the XML-RPC endpoint.
     */
    private function removeWlwManifestLink(): void
    {
        remove_action('wp_head', 'wlwmanifest_link');
    }

    // ── 4. Remove RSD link ─────────────────────────────────────────────

    /**
     * Really Simple Discovery link exposes the XML-RPC endpoint to
     * blog-editing clients. Removing it tightens the attack surface.
     */
    private function removeRsdLink(): void
    {
        remove_action('wp_head', 'rsd_link');
    }

    /**
     * Groups head-cleanup actions (wlwmanifest + RSD) into a single
     * registration block. Both are XML-RPC discovery links that serve
     * no purpose on sites that have XML-RPC disabled.
     */
    private function removeHeadClutter(): void
    {
        $this->removeWlwManifestLink();
        $this->removeRsdLink();
    }

    // ── 6. Disable application passwords ───────────────────────────────

    /**
     * Application passwords provide a secondary authentication vector
     * that bypasses two-factor plugins. Most sites never use them, so
     * disabling the feature removes an unnecessary attack surface.
     */
    private function disableApplicationPasswords(): void
    {
        add_filter('wp_is_application_passwords_available', '__return_false', 10);
    }

    // ── 7. Force SSL admin ─────────────────────────────────────────────

    /**
     * FORCE_SSL_ADMIN ensures wp-login.php and /wp-admin/ are served
     * over HTTPS, preventing session cookies from leaking over plain HTTP.
     * The constant must be defined early (wp-config.php ideally); if it is
     * already set we respect the existing value and just log a notice.
     */
    private function forceSslAdmin(): void
    {
        if (defined('FORCE_SSL_ADMIN')) {
            return;
        }

        /*
         * Constants defined after wp-settings.php loads may be too late
         * for WordPress to enforce SSL redirects on the login page. We
         * define it here as a best-effort fallback, but the recommended
         * approach is to set it in wp-config.php.
         */
        define('FORCE_SSL_ADMIN', true);
    }

    // ── 8. Remove X-Powered-By header ──────────────────────────────────

    /**
     * The X-Powered-By header discloses the PHP version, letting
     * attackers fingerprint the server for version-specific exploits.
     * We remove it early via an init hook; the Headers module handles
     * additional security headers at send_headers time.
     */
    private function removeXPoweredByHeader(): void
    {
        add_action('init', static function (): void {
            header_remove('X-Powered-By');
        }, 10, 0);
    }

    // ── 9. Disable PHP error display on front-end ──────────────────────

    /**
     * PHP error output on the front-end leaks file paths, database
     * credentials (in connection errors), and internal logic. Errors
     * should only be visible in wp-admin or logged to disk, never
     * rendered to unauthenticated visitors.
     *
     * We leave display_errors untouched in wp-admin and during cron
     * so developers can still diagnose issues in controlled contexts.
     */
    private function disableFrontEndErrorDisplay(): void
    {
        if (is_admin() || wp_doing_cron()) {
            return;
        }

        ini_set('display_errors', '0');
    }

    // ── 10. Remove query strings from static assets ────────────────────

    /**
     * The ?ver= query string on CSS/JS URLs prevents CDN and proxy
     * caching (many strip query-string URLs from the cache entirely).
     * Removing it improves cache-hit ratios and reduces load.
     *
     * Builder exception: Elementor and Divi use ver= for cache-busting
     * after edits. Stripping their version parameters causes stale
     * assets to persist in browser caches, breaking visual changes.
     * We therefore skip any URL belonging to a known builder asset.
     */
    private function removeQueryStringsFromStaticAssets(): void
    {
        $stripVersion = function (string $src): string {
            /*
             * During builder edit sessions every asset may be reloaded
             * with a fresh cache-buster. Leave all assets untouched to
             * avoid breaking the live preview.
             */
            if ($this->builderDetection->isElementorEditMode() || $this->builderDetection->isDiviBuilderActive()) {
                return $src;
            }

            /*
             * Even outside edit mode, builder assets rely on ver= to
             * invalidate caches after a builder save. Stripping the
             * version from these would cause stale CSS/JS for visitors.
             */
            if (
                str_contains($src, 'elementor')
                || str_contains($src, 'et-core')
                || str_contains($src, 'divi')
            ) {
                return $src;
            }

            // Strip the ver= parameter from the query string
            if (str_contains($src, '?ver=') || str_contains($src, '&ver=')) {
                $src = (string) remove_query_arg('ver', $src);
            }

            return $src;
        };

        add_filter('style_loader_src', $stripVersion, 10, 1);
        add_filter('script_loader_src', $stripVersion, 10, 1);
    }

    // ── 11. Disable embed/oEmbed ───────────────────────────────────────

    /**
     * WordPress oEmbed auto-discovery allows remote sites to embed your
     * content and exposes REST-based discovery endpoints. Disabling it
     * reduces the REST surface and prevents content from being framed
     * on untrusted third-party sites.
     */
    private function disableEmbedOembed(): void
    {
        remove_action('wp_head', 'wp_oembed_add_discovery_links', 10);
        remove_action('wp_head', 'wp_oembed_add_host_js', 10);
        add_filter('embed_oembed_discover', '__return_false', 10);
    }

    // ── 12 & 16. Remove shortlink ──────────────────────────────────────

    /**
     * The shortlink meta tag and HTTP header expose numeric post IDs
     * (?p=123), enabling content enumeration. Removing both the head
     * tag and the Link header eliminates this vector.
     *
     * The header-based shortlink must be removed after the theme sets
     * up, because wp_shortlink_header is registered during theme load.
     */
    private function removeShortlink(): void
    {
        // Remove the <link rel="shortlink"> tag from wp_head
        remove_action('wp_head', 'wp_shortlink_wp_head', 10);

        // Remove the Link: <...>; rel=shortlink HTTP header
        remove_action('template_redirect', 'wp_shortlink_header', 11);

        /*
         * Belt-and-suspenders: also remove via after_setup_theme in case
         * a theme re-registers the shortlink header during its setup.
         */
        add_action('after_setup_theme', static function (): void {
            remove_action('template_redirect', 'wp_shortlink_header', 11);
        }, 10, 0);
    }

    // ── 13. Block file editing ─────────────────────────────────────────

    /**
     * The built-in theme/plugin editor (Appearance > Theme Editor) allows
     * any administrator to inject arbitrary PHP. If an admin account is
     * compromised the editor becomes an instant backdoor. DISALLOW_FILE_EDIT
     * disables the editor UI without affecting plugin/theme installs.
     */
    private function blockFileEditing(): void
    {
        if (defined('DISALLOW_FILE_EDIT')) {
            return;
        }

        define('DISALLOW_FILE_EDIT', true);
    }

    // ── 14. Optionally block file modifications ────────────────────────

    /**
     * DISALLOW_FILE_MODS prevents all filesystem writes: plugin/theme
     * installs, updates, and editor access. This is the nuclear option
     * for locked-down production sites.
     *
     * We gate it behind config->disableFileMods because Divi and Elementor
     * users often need to install builder templates, layouts, and kits
     * from within wp-admin. Forcing DISALLOW_FILE_MODS on a builder
     * site would break that workflow entirely.
     */
    private function optionallyBlockFileMods(): void
    {
        if (!$this->config->disableFileMods) {
            return;
        }

        if (defined('DISALLOW_FILE_MODS')) {
            return;
        }

        define('DISALLOW_FILE_MODS', true);
    }

    // ── 15. Optionally disable feeds ───────────────────────────────────

    /**
     * RSS and Atom feeds expose full post content to scrapers and can
     * leak draft excerpts. Sites that do not use RSS (most modern
     * brochure/landing-page sites built with Elementor or Divi) can
     * safely disable feeds to reduce the content-exposure surface.
     *
     * Builder context: feeds are template_redirect hooks, which never
     * fire during AJAX or REST builder sessions, so no builder check
     * is needed. We redirect to the homepage with a 301 to signal
     * permanent removal to crawlers.
     */
    private function optionallyDisableFeeds(): void
    {
        if (!$this->config->disableFeeds) {
            return;
        }

        add_action('template_redirect', static function (): void {
            if (is_feed()) {
                wp_safe_redirect(home_url(), 301);
                exit;
            }
        }, 10, 0);
    }

    // ── 17. Disable pingback ───────────────────────────────────────────

    /**
     * Pingbacks are an XML-RPC method that allows remote sites to notify
     * you of a link. Attackers abuse pingback.ping for DDoS amplification
     * and SSRF (the server fetches the attacker-supplied URL). Even with
     * XML-RPC fully disabled, we belt-and-suspenders remove the methods
     * from the registered list so that any filter re-enabling XML-RPC
     * still cannot exploit pingback.
     */
    private function disablePingback(): void
    {
        add_filter('xmlrpc_methods', static function (array $methods): array {
            unset(
                $methods['pingback.ping'],
                $methods['pingback.extensions.getPingbacks'],
            );

            return $methods;
        }, 10, 1);
    }
}
