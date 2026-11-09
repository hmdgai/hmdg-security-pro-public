<?php

declare(strict_types=1);

/** Behavioural regression tests; every HTTP, cache and download operation is isolated. */
define('ABSPATH', __DIR__ . '/');
define('HMDG_SECURITY_VERSION', '1.11.0');

final class WP_Error
{
    public function __construct(public string $code, public string $message = '') {}
}

$GLOBALS['test_context'] = ['admin' => false, 'cron' => false];
$GLOBALS['test_hooks'] = [];
$GLOBALS['test_cache'] = [];
$GLOBALS['test_cache_calls'] = [];
$GLOBALS['test_http'] = [];
$GLOBALS['test_responses'] = [];
$GLOBALS['test_downloads'] = [];
$GLOBALS['test_temp_files'] = [];
$GLOBALS['test_checks'] = 0;

function is_admin(): bool { return $GLOBALS['test_context']['admin']; }
function wp_doing_cron(): bool { return $GLOBALS['test_context']['cron']; }
function is_wp_error(mixed $value): bool { return $value instanceof WP_Error; }
function add_filter(string $name, callable $callback, int $priority = 10, int $args = 1): void
{
    $GLOBALS['test_hooks'][$name][] = ['callback' => $callback, 'priority' => $priority, 'args' => $args];
}
function add_action(string $name, callable $callback, int $priority = 10, int $args = 1): void
{
    add_filter($name, $callback, $priority, $args);
}
function remove_filter(string $name, callable $callback, int $priority = 10): void
{
    $GLOBALS['test_hooks'][$name] = array_values(array_filter($GLOBALS['test_hooks'][$name] ?? [],
        static fn (array $hook): bool => $hook['callback'] !== $callback || $hook['priority'] !== $priority));
}
function wp_cache_get(string $key, string $group = '', bool $force = false, ?bool &$found = null): mixed
{
    $GLOBALS['test_cache_calls'][] = 'get';
    $found = array_key_exists($group . '/' . $key, $GLOBALS['test_cache']);
    return $GLOBALS['test_cache'][$group . '/' . $key] ?? false;
}
function wp_cache_set(string $key, mixed $value, string $group = '', int $ttl = 0): bool
{
    $GLOBALS['test_cache_calls'][] = ['set', $ttl];
    $GLOBALS['test_cache'][$group . '/' . $key] = $value;
    return true;
}
function wp_cache_delete(string $key, string $group = ''): bool
{
    unset($GLOBALS['test_cache'][$group . '/' . $key]);
    return true;
}
function wp_safe_remote_get(string $url, array $args = []): array|WP_Error
{
    $GLOBALS['test_http'][] = [$url, $args];
    return $GLOBALS['test_responses'][$url] ?? new WP_Error('unconfigured_test_request');
}
function wp_remote_retrieve_response_code(array $response): int { return $response['response']['code']; }
function wp_remote_retrieve_body(array $response): string { return $response['body']; }
function esc_html(string $text): string { return htmlspecialchars($text, ENT_QUOTES, 'UTF-8'); }
function get_temp_dir(): string { return sys_get_temp_dir() . '/'; }
function wp_delete_file(string $path): void { if (is_file($path)) { unlink($path); } }
function download_url(string $url, int $timeout = 300): string|WP_Error
{
    $source = $GLOBALS['test_downloads'][$url] ?? null;
    if (!is_string($source)) { return new WP_Error('unconfigured_test_download'); }
    $file = tempnam(sys_get_temp_dir(), 'hmdg-verified-download-');
    copy($source, $file);
    $GLOBALS['test_temp_files'][] = $file;
    return $file;
}

require_once __DIR__ . '/../includes/Services/ObjectCacheService.php';
require_once __DIR__ . '/../includes/Services/ReleaseMetadata.php';
require_once __DIR__ . '/../includes/Services/ProtectedRootPaths.php';
require_once __DIR__ . '/../includes/Services/SignedReleasePackage.php';
require_once __DIR__ . '/../includes/Services/ReleaseUpdater.php';

use HMDG\Security\Services\ObjectCacheService;
use HMDG\Security\Services\ReleaseMetadata;
use HMDG\Security\Services\ReleaseUpdater;
use HMDG\Security\Services\SignedReleasePackage;

function check(bool $condition, string $message): void
{
    $GLOBALS['test_checks']++;
    if (!$condition) { throw new RuntimeException('FAIL: ' . $message); }
}
function resetState(bool $admin = true, bool $cron = false): void
{
    $GLOBALS['test_context'] = ['admin' => $admin, 'cron' => $cron];
    foreach (['test_hooks', 'test_cache', 'test_cache_calls', 'test_http', 'test_responses', 'test_downloads'] as $key) {
        $GLOBALS[$key] = [];
    }
}
function metadata(string $version = '1.12.0'): array
{
    $url = ReleaseMetadata::packageUrl($version);
    return ['tag_name' => 'v' . $version, 'draft' => false, 'prerelease' => false,
        'body' => '<script>not markup</script>', 'published_at' => '2026-11-09T00:00:00Z',
        'assets' => [
            ['name' => 'hmdg-security-pro.zip', 'browser_download_url' => $url, 'size' => 100],
            ['name' => 'hmdg-security-pro.zip.sig', 'browser_download_url' => $url . '.sig', 'size' => 88],
        ]];
}
function archiveFixture(string $version = '1.12.0', array $extra = []): string
{
    $file = tempnam(sys_get_temp_dir(), 'hmdg-archive-test-');
    $GLOBALS['test_temp_files'][] = $file;
    $zip = new ZipArchive();
    $zip->open($file, ZipArchive::OVERWRITE);
    $bootstrap = "<?php\n/**\n * Plugin Name: HMDG Security Pro\n * Version: $version\n */\ndefine('HMDG_SECURITY_VERSION', '$version');\n";
    $zip->addFromString('hmdg-security-pro/hmdg-security-pro.php', $bootstrap);
    $zip->addFromString('hmdg-security-pro/includes/Example.php', '<?php declare(strict_types=1);');
    foreach ($extra as $name => $bytes) { $zip->addFromString($name, $bytes); }
    $zip->close();
    return $file;
}

try {
    if (!function_exists('sodium_crypto_sign_keypair') || !class_exists(ZipArchive::class)) {
        throw new RuntimeException('The signed-updater suite requires sodium and zip extensions.');
    }
    resetState(false);
    $updater = new ReleaseUpdater(new ObjectCacheService());
    $updater->register();
    check($GLOBALS['test_hooks'] === [], 'frontend registers no updater hooks');
    check($updater->updateOffer(false, [], ReleaseUpdater::BASENAME, []) === false, 'frontend does not look up metadata');
    check($GLOBALS['test_cache_calls'] === [] && $GLOBALS['test_http'] === [], 'frontend has zero cache and external operations');
    check(is_wp_error($updater->verifyDownload(false, ReleaseMetadata::packageUrl('1.12.0'))), 'frontend update attempt fails closed');
    check($GLOBALS['test_http'] === [], 'frontend signature callback makes no network calls');

    resetState();
    $updater->register();
    check(isset($GLOBALS['test_hooks']['update_plugins_github.com']), 'scoped native update hook registered');
    check($GLOBALS['test_hooks']['upgrader_pre_download'][0]['args'] === 4, 'download hook receives plugin identity');
    check(!isset($GLOBALS['test_hooks']['upgrader_post_install']), 'no self-deletion or activation hook');
    check($updater->updateOffer(false, [], 'another/another.php', []) === false, 'another github plugin unchanged');
    check($GLOBALS['test_http'] === [], 'another plugin causes no lookup');

    $api = 'https://api.github.com/repos/' . ReleaseUpdater::PUBLIC_REPOSITORY . '/releases/latest';
    $GLOBALS['test_responses'][$api] = ['response' => ['code' => 200], 'body' => json_encode(metadata())];
    $offer = $updater->updateOffer(false, [], ReleaseUpdater::BASENAME, []);
    check(is_array($offer) && $offer['version'] === '1.12.0', 'promoted release is offered to native updater');
    check($offer['package'] === ReleaseMetadata::packageUrl('1.12.0'), 'offer uses exact named release asset');
    $updater->updateOffer(false, [], ReleaseUpdater::BASENAME, []);
    check(count($GLOBALS['test_http']) === 1, 'release metadata cached across repeated checks');
    $lastCache = end($GLOBALS['test_cache_calls']);
    check($GLOBALS['test_http'][0][1]['limit_response_size'] === 262144, 'metadata HTTP response is bounded');
    $info = $updater->pluginInformation(false, 'plugin_information', (object) ['slug' => 'hmdg-security-pro']);
    check(is_object($info) && !str_contains($info->sections['changelog'], '<script>'), 'release notes are escaped');
    check($updater->pluginInformation('untouched', 'query_plugins', (object) []) === 'untouched', 'unrelated Plugin API call unchanged');

    foreach (['draft', 'prerelease'] as $flag) {
        $data = metadata(); $data[$flag] = true;
        check(ReleaseMetadata::validate($data) === null, $flag . ' is never offered');
    }
    foreach (['v1.12.0-beta.1', '1.12.0', 'v1.12.0/evil', "v1.12.0\n"] as $tag) {
        $data = metadata(); $data['tag_name'] = $tag;
        check(ReleaseMetadata::validate($data) === null, 'noncanonical release tag refused');
    }
    $data = metadata(); array_pop($data['assets']);
    check(ReleaseMetadata::validate($data) === null, 'unsigned metadata refused');
    $data = metadata(); $data['assets'][] = $data['assets'][0];
    check(ReleaseMetadata::validate($data) === null, 'duplicate package metadata refused');
    $data = metadata(); $data['assets'][0]['size'] = SignedReleasePackage::MAX_BYTES + 1;
    check(ReleaseMetadata::validate($data) === null, 'oversized package metadata refused');
    $data = metadata(); $data['assets'][1]['size'] = 1025;
    check(ReleaseMetadata::validate($data) === null, 'oversized signature metadata refused');
    $data = metadata(); $data['assets'][0]['browser_download_url'] .= '?token=x';
    check(ReleaseMetadata::validate($data) === null, 'modified package metadata URL refused');

    foreach (['https://github.com.evil.invalid/a.zip', 'http://github.com/' . ReleaseUpdater::PUBLIC_REPOSITORY . '/releases/download/v1.12.0/hmdg-security-pro.zip',
        ReleaseMetadata::packageUrl('1.12.0') . '?x=1', ReleaseMetadata::packageUrl('1.12.0') . '#hash',
        '/tmp/local.zip', 'https://github.com/' . ReleaseUpdater::PUBLIC_REPOSITORY . '/archive/v1.12.0.zip'] as $url) {
        check(ReleaseMetadata::packageVersion($url) === null, 'noncanonical package URL refused');
        check(is_wp_error($updater->verifyDownload(false, $url, null, ['plugin' => ReleaseUpdater::BASENAME])), 'own plugin cannot bypass verification with another package');
    }
    check($updater->verifyDownload('unchanged', 'https://example.invalid/another.zip') === 'unchanged', 'unrelated download override preserved');
    check(is_wp_error($updater->verifyDownload('/tmp/other-filter.zip', ReleaseMetadata::packageUrl('1.12.0'))), 'prior local override cannot bypass authenticity');
    $error = new WP_Error('upstream');
    check($updater->verifyDownload($error, ReleaseMetadata::packageUrl('1.12.0')) === $error, 'upstream error preserved');

    resetState();
    $GLOBALS['test_responses'][$api] = new WP_Error('network');
    $client = new ReleaseMetadata(new ObjectCacheService());
    check($client->latest() === null && $client->latest() === null, 'failed API lookup remains unavailable');
    check(count($GLOBALS['test_http']) === 1, 'failed lookup is cached rather than retried per request');
    $setCalls = array_values(array_filter($GLOBALS['test_cache_calls'], 'is_array'));
    check($setCalls[0][1] >= 3600 && $setCalls[0][1] <= 3900, 'failure backoff is at least one hour');

    resetState();
    $keypair = sodium_crypto_sign_keypair();
    $public = base64_encode(sodium_crypto_sign_publickey($keypair));
    $private = sodium_crypto_sign_secretkey($keypair);
    $file = archiveFixture();
    $bytes = file_get_contents($file);
    $signature = base64_encode(sodium_crypto_sign_detached($bytes, $private));
    check(SignedReleasePackage::verifyBytes($bytes, $signature, $public), 'valid detached Ed25519 signature passes');
    check(!SignedReleasePackage::verifyBytes($bytes . 'tampered', $signature, $public), 'tampered package fails');
    check(!SignedReleasePackage::verifyBytes($bytes, base64_encode(str_repeat('x', 64)), $public), 'wrong signature fails');
    check(!SignedReleasePackage::verifyBytes($bytes, $signature, base64_encode(str_repeat('x', 32))), 'wrong signing key fails');
    check(!SignedReleasePackage::verifyBytes($bytes, 'not base64!', $public), 'malformed signature fails');
    check(!SignedReleasePackage::verifyBytes('', $signature, $public), 'empty package fails');
    check(SignedReleasePackage::validateArchive($file, '1.12.0'), 'correct signed archive structure/version passes');
    check(!SignedReleasePackage::validateArchive($file, '1.13.0'), 'signed old package relabelled newer fails');
    foreach (['sites.json', 'hmdg-security-pro/sites.json', 'hmdg-security-pro/../escape.php', 'hmdg-security-pro/includes/../../escape.php', 'another-plugin/plugin.php'] as $entry) {
        $bad = archiveFixture('1.12.0', [$entry => 'private']);
        check(!SignedReleasePackage::validateArchive($bad, '1.12.0'), 'unsafe or unrelated ZIP entry refused');
    }
    $bad = archiveFixture();
    $zip = new ZipArchive(); $zip->open($bad);
    $zip->addFromString('hmdg-security-pro/includes/link.php', '/outside');
    $zip->setExternalAttributesName('hmdg-security-pro/includes/link.php', ZipArchive::OPSYS_UNIX, 0120777 << 16);
    $zip->close();
    check(!SignedReleasePackage::validateArchive($bad, '1.12.0'), 'ZIP symlink refused');

    $package = ReleaseMetadata::packageUrl('1.12.0');
    $GLOBALS['test_downloads'][$package] = $file;
    $GLOBALS['test_responses'][$package . '.sig'] = ['response' => ['code' => 200], 'body' => $signature];
    $verified = SignedReleasePackage::download($package, $public);
    check(is_string($verified) && is_file($verified), 'verified temporary package handed to native upgrader');
    check(($GLOBALS['test_hooks']['http_request_args'] ?? []) === [], 'temporary download size filter removed');
    $GLOBALS['test_responses'][$package . '.sig']['body'] = '';
    $rejected = SignedReleasePackage::download($package, $public);
    check(is_wp_error($rejected), 'missing signature aborts installation');
    check(!is_file(end($GLOBALS['test_temp_files'])), 'failed temporary download removed');
    $GLOBALS['test_downloads'][$package] = archiveFixture('1.10.0');
    $oldBytes = file_get_contents($GLOBALS['test_downloads'][$package]);
    $GLOBALS['test_responses'][$package . '.sig']['body'] = base64_encode(sodium_crypto_sign_detached($oldBytes, $private));
    check(is_wp_error(SignedReleasePackage::download($package, $public)), 'validly signed downgrade cannot masquerade as a new tag');

    $updater = new ReleaseUpdater(new ObjectCacheService());
    $own = (object) ['plugin' => ReleaseUpdater::BASENAME, 'new_version' => '1.12.0', 'package' => $package];
    check($updater->enableAutomaticUpdate(false, $own) === true, 'valid newer own release opts in to background update');
    check($updater->enableAutomaticUpdate(false, (object) ['plugin' => 'other/other.php']) === false, 'other plugin opt-in unchanged');
    $own->new_version = '1.10.0'; $own->package = ReleaseMetadata::packageUrl('1.10.0');
    check($updater->enableAutomaticUpdate(true, $own) === false, 'automatic downgrade is refused');
    $success = (object) ['item' => (object) ['plugin' => ReleaseUpdater::BASENAME], 'result' => true];
    check($updater->updateEmail(true, [$success]) === false, 'only own successful notification suppressed');
    check($updater->updateEmail(true, [(object) ['item' => $success->item, 'result' => new WP_Error('failed')]]) === true, 'failure notifications preserved');
    check($updater->updateEmail(true, [$success, (object) ['item' => (object) ['plugin' => 'other/other.php'], 'result' => true]]) === true, 'mixed plugin notifications preserved');
    check($updater->updateEmail(true, []) === true, 'empty notification set unchanged');

    resetState(false, true);
    $updater->register();
    check(isset($GLOBALS['test_hooks']['upgrader_pre_download']), 'cron registers signature enforcement before boot return');
    echo 'PASS: ' . $GLOBALS['test_checks'] . " signed-release updater checks\n";
} finally {
    foreach ($GLOBALS['test_temp_files'] as $temporary) { wp_delete_file($temporary); }
}
