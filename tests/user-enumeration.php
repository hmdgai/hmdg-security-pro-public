<?php

declare(strict_types=1);

/** Component tests use real policy methods with inert WordPress dependencies.
 * Pass a WordPress root as the first argument to exercise the real hook engine too.
 * No WordPress configuration, database, plugins or network is loaded.
 */
define('WP_CONTENT_DIR', '/fictional-wordpress/wp-content');
$GLOBALS['enumeration_checks'] = 0;
$GLOBALS['enumeration_hooks'] = [];
$GLOBALS['enumeration_user'] = 0;
$GLOBALS['enumeration_caps'] = [];
$GLOBALS['enumeration_author'] = false;
$GLOBALS['enumeration_nocache'] = 0;

class WP_Error
{
    public function __construct(public string $code, public string $message = '', public array $data = []) {}
}
class WP_HTTP_Response
{
    public function __construct(public mixed $data = null, private int $status = 200) {}
    public function get_status(): int { return $this->status; }
}
class WP_REST_Response extends WP_HTTP_Response {}
class WP_REST_Server
{
    // Match core visibility: calling this wrapper from the module must fail.
    protected function error_to_response(WP_Error $error): WP_REST_Response
    { return rest_convert_error_to_response($error); }
}
class WP_REST_Request
{
    public function __construct(private string $method, private string $route, public array $params = []) {}
    public function get_route(): string { return $this->route; }
    public function get_method(): string { return $this->method; }
}
class EnumerationRedirect extends RuntimeException
{
    public function __construct(public string $url, public int $status) { parent::__construct('Fixture redirect'); }
}
if (isset($argv[1])) {
    require rtrim($argv[1], '/\\') . '/wp-includes/plugin.php';
} else {
    function add_filter(string $hook, callable $callback, int $priority = 10, int $args = 1): void
    { $GLOBALS['enumeration_hooks'][$hook][] = compact('callback', 'priority', 'args'); }
    function add_action(string $hook, callable $callback, int $priority = 10, int $args = 1): void
    { add_filter($hook, $callback, $priority, $args); }
    function apply_filters(string $hook, mixed $value, mixed ...$args): mixed
    {
        $callbacks = $GLOBALS['enumeration_hooks'][$hook] ?? [];
        usort($callbacks, static fn (array $a, array $b): int => $a['priority'] <=> $b['priority']);
        foreach ($callbacks as $entry) {
            $value = ($entry['callback'])(...array_slice([$value, ...$args], 0, $entry['args']));
        }
        return $value;
    }
}
function enumerationHooks(string $hook): array
{
    if (!class_exists(WP_Hook::class)) { return $GLOBALS['enumeration_hooks'][$hook] ?? []; }
    $entries = [];
    foreach (($GLOBALS['wp_filter'][$hook]->callbacks ?? []) as $priority => $callbacks) {
        foreach ($callbacks as $entry) {
            $entries[] = ['callback' => $entry['function'], 'priority' => $priority, 'args' => $entry['accepted_args']];
        }
    }
    return $entries;
}
function is_wp_error(mixed $value): bool { return $value instanceof WP_Error; }
function rest_convert_error_to_response(WP_Error $error): WP_REST_Response
{ return new WP_REST_Response(['code' => $error->code], $error->data['status']); }
function is_user_logged_in(): bool { return $GLOBALS['enumeration_user'] > 0; }
function get_current_user_id(): int { return $GLOBALS['enumeration_user']; }
function current_user_can(string $capability): bool { return in_array($capability, $GLOBALS['enumeration_caps'], true); }
function is_author(): bool { return $GLOBALS['enumeration_author']; }
function is_admin(): bool { return false; }
function wp_doing_cron(): bool { return false; }
function nocache_headers(): void { $GLOBALS['enumeration_nocache']++; }
function home_url(string $path = ''): string { return 'https://fixture.invalid' . $path; }
function wp_safe_redirect(string $location, int $status = 302, string $by = ''): never
{ throw new EnumerationRedirect($location, $status); }
function enumerationCheck(bool $ok, string $message): void
{
    $GLOBALS['enumeration_checks']++;
    if (!$ok) { throw new RuntimeException('FAIL: ' . $message); }
}

require_once __DIR__ . '/../includes/Modules/UserEnumerationProtection.php';
use HMDG\Security\Modules\UserEnumerationProtection;

$policy = new UserEnumerationProtection();
$policy->register();
$server = new WP_REST_Server();
enumerationCheck(enumerationHooks('rest_pre_dispatch')[0]['args'] === 3, 'actual dispatched request is supplied');
enumerationCheck(enumerationHooks('rest_pre_dispatch')[0]['priority'] === PHP_INT_MAX, 'request guard follows ordinary cache filters');
enumerationCheck(enumerationHooks('rest_post_dispatch')[0]['priority'] === PHP_INT_MAX, 'response guard follows ordinary cache filters');
enumerationCheck(enumerationHooks('template_redirect')[0]['priority'] < 10, 'author guard precedes canonical redirects');
enumerationCheck(enumerationHooks('rest_authentication_errors') === [], 'policy never modifies authentication results');
enumerationCheck(!$policy->sendNoCacheHeaders(false) && $policy->sendNoCacheHeaders(true), 'unrelated cache decisions remain unchanged');
add_filter('rest_send_nocache_headers', static fn (bool $send): bool => false, 99, 1);
enumerationCheck(!apply_filters('rest_send_nocache_headers', false), 'ordinary request cache policy is unchanged by guard');

$userRoutes = ['/wp/v2/users', '/wp/v2/users/', '/WP/v2/UsErS', '/wp/v2/users/7', '/wp/v2/users/me', '/wp/v2/users/7/'];
foreach ($userRoutes as $route) {
    foreach (['GET', 'HEAD', 'POST', 'PUT', 'DELETE'] as $method) {
        foreach ([[], ['search' => 'fixture', 'include' => [7], '_fields' => 'id,name,slug', 'context' => 'view']] as $params) {
            $result = $policy->protectRestRequest(null, $server, new WP_REST_Request($method, $route, $params));
            enumerationCheck($result instanceof WP_Error && $result->code === 'rest_user_enumeration_blocked'
                && $result->data['status'] === 403, 'anonymous ' . $method . ' ' . $route . ' is denied');
        }
    }
}
enumerationCheck($policy->sendNoCacheHeaders(false), 'a policy denial requests scoped no-cache headers');
enumerationCheck(apply_filters('rest_send_nocache_headers', false), 'later ordinary cache filter cannot remove denial no-cache');

// Forged builder flags never change authorisation; outer globals never select the protected route.
$_GET = ['et_fb_preview' => 'fixture', 'et_fb_activation_nonce' => 'fixture', 'elementor-preview' => '7'];
$_REQUEST = $_GET;
define('ET_BUILDER_VERSION', 'fixture');
define('ELEMENTOR_PRO_VERSION', 'fixture');
$GLOBALS['wp'] = (object) ['query_vars' => ['rest_route' => '/wp/v2/posts']];
$request = new WP_REST_Request('GET', '/wp/v2/users/7');
enumerationCheck($policy->protectRestRequest(null, $server, $request) instanceof WP_Error,
    'embedded/internal user request is denied regardless of outer route or builder flags');
foreach ([new WP_REST_Response(['id' => 7]), ['id' => 7], true] as $cachedSuccess) {
    enumerationCheck($policy->protectRestRequest($cachedSuccess, $server, $request) instanceof WP_Error,
        'precomputed successful user response cannot bypass the policy');
}
foreach ([new WP_Error('earlier_denial'), new WP_REST_Response(null, 401), new WP_HTTP_Response(null, 503)] as $error) {
    enumerationCheck($policy->protectRestRequest($error, $server, $request) === $error, 'existing denial retains identity');
    enumerationCheck($policy->protectRestResponse($error, $server, $request) === $error, 'existing response denial retains identity');
}

// Typical cache filters may short-circuit dispatch or replace the endpoint response.
// Register after the module to expose ordering errors rather than invoking its method alone.
foreach ([20, 99] as $priority) {
    $cache = static fn (mixed $prior): WP_REST_Response => new WP_REST_Response(['id' => 7]);
    add_filter('rest_pre_dispatch', $cache, $priority, 1);
    add_filter('rest_post_dispatch', $cache, $priority, 1);
    enumerationCheck(apply_filters('rest_pre_dispatch', null, $server, $request) instanceof WP_Error,
        'pre-dispatch cached success at priority ' . $priority . ' cannot reveal users');
    $response = apply_filters('rest_post_dispatch', new WP_REST_Response(['id' => 7]), $server, $request);
    enumerationCheck($response instanceof WP_REST_Response && $response->get_status() === 403,
        'post-dispatch cached success at priority ' . $priority . ' becomes a valid REST denial response');
}

$unrelatedRoutes = ['/wp/v2/posts', '/wp/v2/users-statistics', '/custom/wp/v2/users', '/wc/v3/orders',
    '/elementor/v1/documents', '/et/v1/layouts', '/hmdg-ccm/v1/book-now', '/hmdg-ccm/v1/booking-complete',
    '/hmdg-ccm/v1/nonce', '/hmdg-ccm/v1/verify'];
foreach ($unrelatedRoutes as $route) {
    foreach ([null, true, false, new WP_REST_Response(['fixture' => true]), new WP_Error('existing')] as $prior) {
        enumerationCheck($policy->protectRestRequest($prior, $server, new WP_REST_Request('GET', $route)) === $prior,
            'unrelated route/result unchanged: ' . $route);
        enumerationCheck($policy->protectRestResponse($prior, $server, new WP_REST_Request('GET', $route)) === $prior,
            'unrelated response unchanged: ' . $route);
    }
}

$roles = ['administrator' => ['list_users'], 'editor' => ['edit_posts', 'edit_others_posts'],
    'author' => ['edit_posts', 'publish_posts'], 'contributor' => ['edit_posts'], 'subscriber' => ['read']];
foreach ($roles as $role => $capabilities) {
    $GLOBALS['enumeration_user'] = 7;
    $GLOBALS['enumeration_caps'] = $capabilities;
    $mayList = $role !== 'subscriber';
    foreach (['/wp/v2/users', '/wp/v2/users/8'] as $route) {
        $result = $policy->protectRestRequest(null, $server, new WP_REST_Request('GET', $route));
        enumerationCheck($mayList ? $result === null : $result instanceof WP_Error, $role . ' collection/other profile policy');
    }
    foreach ([['search' => 'fixture', 'context' => 'view'], ['who' => 'authors', 'context' => 'view']] as $params) {
        $result = $policy->protectRestRequest(null, $server, new WP_REST_Request('GET', '/wp/v2/users', $params));
        enumerationCheck($mayList ? $result === null : $result instanceof WP_Error,
            $role . ' collection search/autocomplete is delegated to core only with editorial capability');
    }
    foreach (['/wp/v2/users/me', '/wp/v2/users/7', '/WP/v2/UsErS/0007/'] as $route) {
        foreach (['GET', 'PUT', 'DELETE'] as $method) {
            enumerationCheck($policy->protectRestRequest(null, $server, new WP_REST_Request($method, $route)) === null,
                $role . ' own-profile ' . $method . ' still requires core permission checks');
        }
    }
    $coreDenial = new WP_Error('rest_cannot_edit');
    enumerationCheck($policy->protectRestRequest($coreDenial, $server, $request) === $coreDenial,
        $role . ' cannot override a core/earlier denial');
    $ownRequest = new WP_REST_Request('GET', '/wp/v2/users/me');
    $ownResponse = new WP_REST_Response(['id' => 7]);
    enumerationCheck($policy->protectRestResponse($ownResponse, $server, $ownRequest) === $ownResponse,
        $role . ' authorised own response retains identity');
}

// Cookie-without-REST-nonce authentication can leave the dispatched user anonymous.
$GLOBALS['enumeration_user'] = 0;
$GLOBALS['enumeration_caps'] = ['list_users'];
enumerationCheck($policy->protectRestRequest(null, $server, $request) instanceof WP_Error,
    'post-auth anonymous state wins over stale capabilities/cookies');
foreach (['1', '999999', '01', '-1', '1e0', '', ['malformed'], null] as $author) {
    $_GET = ['author' => $author, 'et_fb_preview' => 'fixture'];
    $before = $GLOBALS['enumeration_nocache'];
    try {
        $policy->protectAuthorRequest();
        throw new RuntimeException('Expected generic redirect');
    } catch (EnumerationRedirect $redirect) {
        enumerationCheck($redirect->url === 'https://fixture.invalid/' && $redirect->status === 302,
            'all author parameter shapes receive the same generic redirect');
        enumerationCheck($GLOBALS['enumeration_nocache'] === $before + 1, 'author denial is not cacheable');
    }
}
$_GET = [];
$GLOBALS['enumeration_author'] = true;
try { $policy->protectAuthorRequest(); throw new RuntimeException('Expected archive redirect'); }
catch (EnumerationRedirect $redirect) { enumerationCheck($redirect->url === 'https://fixture.invalid/', 'public author archive is generic'); }
$GLOBALS['enumeration_user'] = 7;
$GLOBALS['enumeration_caps'] = ['edit_posts', 'edit_others_posts'];
$policy->protectAuthorRequest();
enumerationCheck(true, 'authorised editor archive remains available');
$GLOBALS['enumeration_user'] = 0;
$GLOBALS['enumeration_author'] = false;
$before = $GLOBALS['enumeration_nocache'];
$policy->protectAuthorRequest();
enumerationCheck($GLOBALS['enumeration_nocache'] === $before, 'ordinary page is not marked no-cache');

echo 'PASS: ', $GLOBALS['enumeration_checks'], ' enumeration component checks',
    class_exists(WP_Hook::class) ? ' with WordPress hook engine' : ' with stub hook engine',
    " (real HTTP integration is separate)\n";
