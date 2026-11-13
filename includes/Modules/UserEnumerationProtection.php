<?php

declare(strict_types=1);

namespace HMDG\Security\Modules;

/**
 * Prevent unauthorised account enumeration without altering authentication.
 *
 * Runs on the dispatched REST request, including embedded/batch requests,
 * after authentication has established the current user. No scanner, logger,
 * storage or network dependency is needed on these visitor-facing paths.
 *
 * @package HMDG\Security\Modules
 */
final class UserEnumerationProtection
{
    private bool $deniedRestRequest = false;

    /** @return void Register before context early returns so internal dispatch is covered. */
    public function register(): void
    {
        add_filter('rest_pre_dispatch', [$this, 'protectRestRequest'], PHP_INT_MAX, 3);
        add_filter('rest_post_dispatch', [$this, 'protectRestResponse'], PHP_INT_MAX, 3);
        add_filter('rest_send_nocache_headers', [$this, 'sendNoCacheHeaders'], PHP_INT_MAX, 1);
        add_action('template_redirect', [$this, 'protectAuthorRequest'], 0, 0);
    }

    /**
     * @param mixed $result Earlier dispatch result; unrelated responses retain their identity.
     * @param \WP_REST_Server $server REST server (core still owns endpoint permissions).
     * @param \WP_REST_Request $request Actual request, not the outer URL/global query.
     * @return mixed Existing result or an enumeration denial.
     * @security A cached successful result must not bypass account-data authorisation.
     */
    public function protectRestRequest(mixed $result, \WP_REST_Server $server, \WP_REST_Request $request): mixed
    {
        $route = $request->get_route();
        if (preg_match('#^/wp/v2/users(?:/|$)#i', $route) !== 1) {
            return $result;
        }
        if (is_wp_error($result) || ($result instanceof \WP_HTTP_Response && $result->get_status() >= 400)) {
            return $result;
        }
        if ($this->mayReadUsers($route)) {
            return $result;
        }

        $this->deniedRestRequest = true;
        return new \WP_Error(
            'rest_user_enumeration_blocked',
            'User enumeration via the REST API is disabled.',
            ['status' => 403],
        );
    }

    /**
     * @param mixed $result Response after endpoint and ordinary cache filters have run.
     * @param \WP_REST_Server $server Current REST server; core still owns endpoint permissions.
     * @param \WP_REST_Request $request Actual outer or embedded request.
     * @return mixed Existing response or a REST response containing the policy denial.
     * @security A later successful cache response must not undo the pre-dispatch policy.
     */
    public function protectRestResponse(mixed $result, \WP_REST_Server $server, \WP_REST_Request $request): mixed
    {
        $guarded = $this->protectRestRequest($result, $server, $request);
        if ($guarded === $result || !is_wp_error($guarded)) {
            return $guarded;
        }
        return rest_convert_error_to_response($guarded);
    }

    /** @param bool $send Existing core/plugin cache decision. @return bool Preserve it or protect this denial. */
    public function sendNoCacheHeaders(bool $send): bool
    {
        return $send || $this->deniedRestRequest;
    }

    /**
     * @return void Redirect before core's priority-10 canonical author-slug redirect.
     * @security Builder URL flags are not authorisation; malformed author values also receive the generic outcome.
     */
    public function protectAuthorRequest(): void
    {
        if ((!is_author() && !array_key_exists('author', $_GET)) || $this->mayListUsers()) {
            return;
        }
        nocache_headers();
        wp_safe_redirect(home_url('/'), 302, 'HMDG Security Pro');
        exit;
    }

    /** @param string $route User endpoint route. @return bool Only authorised content users or a user's own profile. */
    private function mayReadUsers(string $route): bool
    {
        if (!is_user_logged_in()) {
            return false;
        }
        if ($this->mayListUsers()) {
            return true;
        }
        if (preg_match('#^/wp/v2/users/(me|[0-9]+)/?$#i', $route, $matches) !== 1) {
            return false;
        }
        return strcasecmp($matches[1], 'me') === 0 || (int) $matches[1] === get_current_user_id();
    }

    /** @return bool Whether the authenticated user may enumerate accounts for administrative/editorial work. */
    private function mayListUsers(): bool
    {
        return is_user_logged_in() && (current_user_can('list_users') || current_user_can('edit_posts'));
    }
}
