<?php

declare(strict_types=1);

namespace HMDG\Security\Services;

/**
 * Native WordPress updates from promoted, signed public GitHub releases.
 *
 * @package HMDG\Security
 * @since 1.11.0
 */
final class ReleaseUpdater
{
    public const PUBLIC_REPOSITORY = 'hmdgai/hmdg-security-pro-public';
    public const PUBLIC_KEY = '7+7jnEFQP8jHg6qxXou8eOvwRrpHHs7mjBzKQjC7cIw=';
    public const BASENAME = 'hmdg-security-pro/hmdg-security-pro.php';
    private readonly ReleaseMetadata $metadata;

    /** @param ObjectCacheService $cacheService Existing plugin-scoped cache. */
    public function __construct(ObjectCacheService $cacheService, private readonly ?LogService $logService = null)
    {
        $this->metadata = new ReleaseMetadata($cacheService, $logService);
    }

    /** @return void Register only where WordPress may legitimately check or install updates. */
    public function register(): void
    {
        if (!ReleaseMetadata::allowedContext()) {
            return;
        }
        add_filter('update_plugins_github.com', [$this, 'updateOffer'], 10, 4);
        add_filter('plugins_api', [$this, 'pluginInformation'], 20, 3);
        add_filter('upgrader_pre_download', [$this, 'verifyDownload'], 10, 4);
        add_filter('auto_update_plugin', [$this, 'enableAutomaticUpdate'], 10, 2);
        add_filter('auto_plugin_update_send_email', [$this, 'updateEmail'], 10, 2);
        add_action('upgrader_process_complete', [$this, 'upgradeComplete'], 10, 2);
    }

    /**
     * @param array|false $offer Prior update offer for this hostname.
     * @param array<string, mixed> $pluginData Native plugin headers.
     * @param string $pluginFile Exact installed plugin basename.
     * @param list<string> $locales Installed locales (no translation package is supplied).
     * @return array|false Native update details for this plugin only.
     */
    public function updateOffer(array|false $offer, array $pluginData, string $pluginFile, array $locales): array|false
    {
        if ($pluginFile !== self::BASENAME || !ReleaseMetadata::allowedContext()) {
            return $offer;
        }
        $release = $this->metadata->latest();
        if ($release === null) {
            return false;
        }
        return ['id' => 'https://github.com/' . self::PUBLIC_REPOSITORY, 'slug' => 'hmdg-security-pro',
            'version' => $release['version'], 'url' => 'https://github.com/' . self::PUBLIC_REPOSITORY,
            'package' => $release['package'], 'requires_php' => '8.2', 'requires' => '6.4', 'autoupdate' => true];
    }

    /**
     * @param mixed $result Prior Plugin API result; preserve unrelated results.
     * @param string $action Plugin API action.
     * @param object $args Plugin API arguments.
     * @return mixed Scoped native plugin details.
     */
    public function pluginInformation(mixed $result, string $action, object $args): mixed
    {
        if ($action !== 'plugin_information' || ($args->slug ?? '') !== 'hmdg-security-pro'
            || !ReleaseMetadata::allowedContext()) {
            return $result;
        }
        $release = $this->metadata->latest();
        return $release === null ? $result : (object) [
            'name' => 'HMDG Security Pro', 'slug' => 'hmdg-security-pro', 'version' => $release['version'],
            'author' => 'HMDG', 'homepage' => 'https://hmdg.co.uk', 'requires' => '6.4', 'requires_php' => '8.2',
            'download_link' => $release['package'], 'last_updated' => $release['published'],
            'sections' => ['description' => 'Security hardening for HMDG-managed WordPress sites.',
                'changelog' => nl2br(esc_html($release['notes']))],
        ];
    }

    /**
     * @param mixed $reply Prior download override.
     * @param string $package Download URL or local path supplied to the native upgrader.
     * @param object|null $upgrader Native upgrader instance.
     * @param array<string, mixed> $hookExtra Native plugin identity.
     * @return mixed Verified temporary file, refusal, or unchanged unrelated result.
     */
    public function verifyDownload(mixed $reply, string $package = '', ?object $upgrader = null, array $hookExtra = []): mixed
    {
        $ours = ($hookExtra['plugin'] ?? null) === self::BASENAME
            || (is_array($hookExtra['plugins'] ?? null) && in_array(self::BASENAME, $hookExtra['plugins'], true))
            || ReleaseMetadata::packageVersion($package) !== null;
        if (!$ours || is_wp_error($reply)) {
            return $reply;
        }
        if (!ReleaseMetadata::allowedContext()) {
            return new \WP_Error('hmdg_security_invalid_context', 'HMDG Security Pro updates require an administrative update context.');
        }
        if ($reply !== false || ReleaseMetadata::packageVersion($package) === null) {
            return new \WP_Error('hmdg_security_untrusted_package', 'HMDG Security Pro requires an exact signed release URL.');
        }
        $result = SignedReleasePackage::download($package, self::PUBLIC_KEY);
        if (is_wp_error($result)) {
            $this->logService?->warning('ReleaseUpdater', 'Signed release installation refused; keeping the installed version.');
        }
        return $result;
    }

    /** @param bool|null $enabled Existing choice. @param object $item Native update offer. @return bool|null Scoped opt-in. */
    public function enableAutomaticUpdate(?bool $enabled, object $item): ?bool
    {
        if (($item->plugin ?? '') !== self::BASENAME) {
            return $enabled;
        }
        $version = is_string($item->package ?? null) ? ReleaseMetadata::packageVersion($item->package) : null;
        return $version !== null && ($item->new_version ?? null) === $version
            && version_compare($version, HMDG_SECURITY_VERSION, '>');
    }

    /**
     * Suppress only an all-success result set consisting entirely of this plugin.
     *
     * @param bool $enabled Existing notification decision.
     * @param array<object> $results Native automatic plugin-update results.
     * @return bool Never suppress failures or updates to other plugins.
     */
    public function updateEmail(bool $enabled, array $results): bool
    {
        if ($results === []) {
            return $enabled;
        }
        foreach ($results as $result) {
            if (!is_object($result) || ($result->item->plugin ?? '') !== self::BASENAME
                || ($result->result ?? false) !== true) {
                return $enabled;
            }
        }
        return false;
    }

    /** @param object $upgrader Native upgrader. @param array<string, mixed> $extra Native completion data. @return void */
    public function upgradeComplete(object $upgrader, array $extra): void
    {
        $plugins = is_array($extra['plugins'] ?? null) ? $extra['plugins'] : [$extra['plugin'] ?? ''];
        if (($extra['type'] ?? '') === 'plugin' && in_array(self::BASENAME, $plugins, true)) {
            $this->metadata->clear();
        }
    }
}
