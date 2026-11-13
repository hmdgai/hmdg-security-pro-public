<?php

declare(strict_types=1);

namespace HMDG\Security\Admin;

use HMDG\Security\SecurityConfig;
use HMDG\Security\Services\ObjectCacheService;

/**
 * Top-level HMDG Security admin page (v1.5.0).
 *
 * This is an OPERATIONS UI, not a settings UI. It surfaces two tables:
 *   - Active lockouts (with Unlock action)
 *   - Malware quarantine (with Delete / False-positive actions)
 *
 * There is NO configuration here. Thresholds, alert recipient, scan
 * cadences, allowlists — all remain code-only in SecurityConfig.
 * This class is a deliberate exception to the `.claude/decisions.md`
 * "no admin UI" rule, scoped tightly to operations only, per the
 * explicit operator ask for v1.5.0.
 *
 * Performance posture:
 *   - Class is instantiated ONLY in admin context (is_admin or cron
 *     or WP-CLI, never anonymous front-end).
 *   - All CSS is inlined into admin_head-<hookname> so it ONLY loads
 *     on this page. Zero external requests. Zero JS bundles.
 *   - Total admin-page PHP CPU under 50ms: 1 cached count, 1 indexed
 *     SELECT, fixed-size WP_List_Table render.
 *
 * @since 1.5.0
 */
final class AdminPage
{
    /** Menu slug — also the $_GET['page'] value. */
    public const MENU_SLUG = 'hmdg-security';

    /** Capability required to view or action the page. */
    public const CAPABILITY = 'manage_options';

    /** The WP-generated screen hook suffix (assigned during register()). */
    private string $hookSuffix = '';

    /** @var array<string, int>|null */
    private ?array $quarantineCounts = null;

    public function __construct(
        private readonly ObjectCacheService $cacheService,
        private readonly FindingsRepository $repository,
        private readonly LockoutLogRepository $lockoutLogRepo,
        private readonly SecurityConfig $config,
    ) {}

    public function register(): void
    {
        add_action('admin_menu', [$this, 'registerMenu']);
    }

    public function registerMenu(): void
    {
        $this->hookSuffix = (string) add_menu_page(
            __('HMDG Security', 'hmdg-security-pro'),
            __('HMDG Security', 'hmdg-security-pro'),
            self::CAPABILITY,
            self::MENU_SLUG,
            [$this, 'render'],
            'dashicons-shield-alt',
            80,
        );

        // CSS loads ONLY on our page — admin_head is emitted in the
        // <head> of the rendered admin document. Using the suffixed
        // variant keeps it scoped.
        add_action('admin_head-' . $this->hookSuffix, [$this, 'outputStyles']);
    }

    public function render(): void
    {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to view this page.', 'hmdg-security-pro'));
        }

        $tab = $this->currentTab();

        $this->renderHeader(activeTab: $tab);
        $this->renderNotice();

        echo '<div class="hmdg-panel">';

        if ($tab === 'lockouts') {
            $this->renderLockouts();
        } else {
            $this->renderQuarantine();
        }

        echo '</div>';
        echo '</div>'; // .hmdg-wrap
    }

    private function currentTab(): string
    {
        $tab = isset($_GET['tab']) ? sanitize_key((string) $_GET['tab']) : 'quarantine';

        return in_array($tab, ['quarantine', 'lockouts'], true) ? $tab : 'quarantine';
    }

    private function renderHeader(string $activeTab): void
    {
        $quarantineUrl = admin_url('admin.php?page=' . self::MENU_SLUG . '&tab=quarantine');
        $lockoutsUrl   = admin_url('admin.php?page=' . self::MENU_SLUG . '&tab=lockouts');

        $quarantineCounts = $this->quarantineCounts();
        $quarantineCount = $quarantineCounts[FindingsRepository::STATUS_QUARANTINED] ?? 0;

        echo '<div class="wrap hmdg-wrap">';
        echo '<div class="hmdg-hero">';
        echo '<div class="hmdg-hero__inner">';
        echo '<div class="hmdg-hero__brand">';
        echo '<div class="hmdg-hero__logo" aria-hidden="true">';
        echo '<span class="hmdg-hero__shield">🛡</span>';
        echo '</div>';
        echo '<div class="hmdg-hero__text">';
        echo '<h1>' . esc_html__('HMDG Security', 'hmdg-security-pro') . '</h1>';
        echo '<p class="hmdg-hero__tagline">' . esc_html__('Operations dashboard · real-time visibility into lockouts and quarantined malware', 'hmdg-security-pro') . '</p>';
        echo '</div>';
        echo '</div>';

        echo '<div class="hmdg-hero__stats">';
        echo '<div class="hmdg-stat">';
        echo '<div class="hmdg-stat__value">' . esc_html((string) $quarantineCount) . '</div>';
        echo '<div class="hmdg-stat__label">' . esc_html__('In quarantine', 'hmdg-security-pro') . '</div>';
        echo '</div>';
        echo '<div class="hmdg-stat">';
        echo '<div class="hmdg-stat__value">' . esc_html($this->config->alertEmail ?: '—') . '</div>';
        echo '<div class="hmdg-stat__label">' . esc_html__('Alerts route to', 'hmdg-security-pro') . '</div>';
        echo '</div>';
        echo '</div>';
        echo '</div>'; // hero__inner
        echo '</div>'; // hmdg-hero

        echo '<nav class="hmdg-tabs" aria-label="' . esc_attr__('HMDG Security sections', 'hmdg-security-pro') . '">';
        $this->renderTab(
            url: $quarantineUrl,
            label: __('Malware Quarantine', 'hmdg-security-pro'),
            icon: '🧪',
            active: $activeTab === 'quarantine',
        );
        $this->renderTab(
            url: $lockoutsUrl,
            label: __('Active Lockouts', 'hmdg-security-pro'),
            icon: '🔒',
            active: $activeTab === 'lockouts',
        );
        echo '</nav>';
    }

    private function renderTab(string $url, string $label, string $icon, bool $active): void
    {
        $classes = 'hmdg-tab';
        if ($active) {
            $classes .= ' hmdg-tab--active';
        }
        printf(
            '<a href="%s" class="%s"><span class="hmdg-tab__icon" aria-hidden="true">%s</span>%s</a>',
            esc_url($url),
            esc_attr($classes),
            esc_html($icon),
            esc_html($label),
        );
    }

    private function renderNotice(): void
    {
        $status = isset($_GET['hmdg_notice']) ? sanitize_key((string) $_GET['hmdg_notice']) : '';
        if ($status === '') {
            return;
        }

        [$class, $message] = $this->noticeFor(status: $status);
        if ($message === '') {
            return;
        }

        printf(
            '<div class="hmdg-notice hmdg-notice--%s" role="status">%s</div>',
            esc_attr($class),
            esc_html($message),
        );
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function noticeFor(string $status): array
    {
        return match ($status) {
            'unlocked'        => ['success', __('Lockout cleared. That IP can attempt login again.', 'hmdg-security-pro')],
            'deleted'         => ['success', __('Quarantined file permanently deleted.', 'hmdg-security-pro')],
            'restored'        => ['success', __('File restored. Marked as false positive.', 'hmdg-security-pro')],
            'delete_failed'   => ['error', __('Could not delete that quarantined file — check the security log.', 'hmdg-security-pro')],
            'restore_failed'  => ['error', __('Could not restore that file — check the security log. (A file may already exist at the original path.)', 'hmdg-security-pro')],
            'invalid_input'   => ['error', __('Invalid request.', 'hmdg-security-pro')],
            'forbidden'       => ['error', __('You do not have permission for that action.', 'hmdg-security-pro')],
            'nonce_failed'    => ['error', __('Security check failed. Reload the page and try again.', 'hmdg-security-pro')],
            'rate_limited'    => ['warning', __('Too many actions in a short window. Slow down and try again in a minute.', 'hmdg-security-pro')],
            default           => ['', ''],
        };
    }

    private function renderLockouts(): void
    {
        $table = new LockoutsListTable(
            cacheService: $this->cacheService,
            config: $this->config,
        );
        $table->prepare_items();

        echo '<div class="hmdg-card">';
        echo '<div class="hmdg-card__header">';
        echo '<h2>' . esc_html__('Active Lockouts', 'hmdg-security-pro') . '</h2>';
        echo '<p class="hmdg-card__subtitle">' . esc_html__('IPs currently blocked by LoginProtection. Unlock one to give that attacker another free attempt — use sparingly.', 'hmdg-security-pro') . '</p>';
        echo '</div>';
        echo '<div class="hmdg-card__body">';
        $table->display();
        echo '<h2 class="hmdg-section-heading">' . esc_html__('Lockout History (last 30 days)', 'hmdg-security-pro') . '</h2>';

        $history = new LockoutHistoryListTable($this->lockoutLogRepo);
        $history->prepare_items();
        $history->display();
        echo '</div>';
        echo '</div>';
    }

    private function renderQuarantine(): void
    {
        $status = isset($_GET['status']) ? sanitize_key((string) $_GET['status']) : FindingsRepository::STATUS_QUARANTINED;
        $table = new QuarantineListTable(
            repository: $this->repository,
            status: $status,
        );
        $table->prepare_items();

        echo '<div class="hmdg-card">';
        echo '<div class="hmdg-card__header">';
        echo '<h2>' . esc_html__('Malware Quarantine', 'hmdg-security-pro') . '</h2>';
        echo '<p class="hmdg-card__subtitle">' . esc_html__('Scan findings, including HighRisk detections, are flagged for review without moving files. Existing quarantined files retain their delete and false-positive restore controls.', 'hmdg-security-pro') . '</p>';
        echo '<div class="hmdg-subtabs">';
        $this->renderSubtab(
            status: FindingsRepository::STATUS_QUARANTINED,
            label: __('Quarantined', 'hmdg-security-pro'),
            current: $status,
        );
        $this->renderSubtab(
            status: FindingsRepository::STATUS_DELETED,
            label: __('Deleted', 'hmdg-security-pro'),
            current: $status,
        );
        $this->renderSubtab(
            status: FindingsRepository::STATUS_FALSE_POSITIVE,
            label: __('False positives', 'hmdg-security-pro'),
            current: $status,
        );
        $this->renderSubtab(
            status: FindingsRepository::STATUS_FLAGGED,
            label: __('Flagged for review', 'hmdg-security-pro'),
            current: $status,
        );
        echo '</div>';
        echo '</div>';

        echo '<div class="hmdg-card__body">';
        $table->display();
        echo '</div>';
        echo '</div>';
    }

    private function renderSubtab(string $status, string $label, string $current): void
    {
        $url = admin_url('admin.php?page=' . self::MENU_SLUG . '&tab=quarantine&status=' . rawurlencode($status));
        $classes = 'hmdg-subtab';
        if ($status === $current) {
            $classes .= ' hmdg-subtab--active';
        }
        $counts = $this->quarantineCounts();
        $count = $counts[$status] ?? 0;

        printf(
            '<a href="%s" class="%s">%s <span class="hmdg-subtab__count">%s</span></a>',
            esc_url($url),
            esc_attr($classes),
            esc_html($label),
            esc_html((string) $count),
        );
    }

    /**
     * Inline premium stylesheet. Emitted only on the HMDG Security
     * page via admin_head-<hookname>. Scope-prefixed with .hmdg-
     * classes so it cannot bleed into other admin screens.
     */
    public function outputStyles(): void
    {
        echo <<<'CSS'
<style id="hmdg-security-admin-styles">
.hmdg-wrap { margin: 0; padding: 0 20px 40px; max-width: 1400px; }
.hmdg-wrap h1, .hmdg-wrap h2, .hmdg-wrap h3 { color: #0f172a; }

/* Hero */
.hmdg-hero {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 55%, #312e81 100%);
    color: #f8fafc;
    border-radius: 16px;
    padding: 28px 32px;
    margin: 24px 0 0;
    box-shadow: 0 10px 30px -10px rgba(15, 23, 42, 0.35);
}
.hmdg-hero__inner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 24px;
}
.hmdg-hero__brand { display: flex; align-items: center; gap: 18px; }
.hmdg-hero__logo {
    width: 56px;
    height: 56px;
    border-radius: 14px;
    background: rgba(255,255,255,0.08);
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: inset 0 0 0 1px rgba(255,255,255,0.08);
}
.hmdg-hero__shield { font-size: 28px; filter: drop-shadow(0 2px 4px rgba(0,0,0,0.25)); }
.hmdg-hero__text h1 { color: #fff; font-size: 24px; line-height: 1.1; margin: 0; font-weight: 700; letter-spacing: -0.02em; }
.hmdg-hero__tagline { margin: 6px 0 0; color: #cbd5f5; font-size: 13px; font-weight: 400; }
.hmdg-hero__stats { display: flex; gap: 28px; }
.hmdg-stat {
    min-width: 150px;
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.08);
    padding: 12px 16px;
    border-radius: 12px;
    backdrop-filter: blur(6px);
}
.hmdg-stat__value { font-size: 22px; font-weight: 700; color: #fff; letter-spacing: -0.01em; }
.hmdg-stat__label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #a5b4fc; margin-top: 4px; }

/* Primary tabs */
.hmdg-tabs {
    display: flex;
    gap: 4px;
    margin: 24px 0 0;
    padding: 6px;
    background: #f1f5f9;
    border-radius: 12px;
    width: fit-content;
}
.hmdg-tab {
    padding: 10px 18px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    color: #475569;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    transition: background 120ms ease, color 120ms ease, box-shadow 120ms ease;
}
.hmdg-tab:hover { color: #0f172a; background: rgba(255,255,255,0.6); }
.hmdg-tab--active {
    background: #fff;
    color: #0f172a;
    box-shadow: 0 1px 2px rgba(15,23,42,0.08), 0 0 0 1px rgba(15,23,42,0.04);
}
.hmdg-tab__icon { font-size: 16px; }

/* Panel / card */
.hmdg-panel { margin-top: 20px; }
.hmdg-section-heading {
    margin: 22px 8px 12px;
    font-size: 15px;
    font-weight: 700;
    color: #0f172a;
}
.hmdg-card {
    background: #fff;
    border: 1px solid #e2e8f0;
    border-radius: 14px;
    overflow: hidden;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
}
.hmdg-card__header {
    padding: 20px 24px 16px;
    border-bottom: 1px solid #e2e8f0;
    background: linear-gradient(180deg, #fff 0%, #f8fafc 100%);
}
.hmdg-card__header h2 { margin: 0; font-size: 17px; font-weight: 700; letter-spacing: -0.01em; }
.hmdg-card__subtitle { margin: 6px 0 0; color: #64748b; font-size: 13px; }
.hmdg-card__body { padding: 6px 6px 8px; }
.hmdg-card__body .wp-list-table { border: none; margin: 0; }
.hmdg-card__body .wp-list-table thead th {
    background: #f8fafc;
    color: #475569;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    border-bottom: 1px solid #e2e8f0;
    padding: 10px 14px;
}
.hmdg-card__body .wp-list-table tbody td {
    padding: 14px;
    border-bottom: 1px solid #f1f5f9;
    vertical-align: middle;
}
.hmdg-card__body .wp-list-table tbody tr:hover { background: #f8fafc; }
.hmdg-card__body .tablenav { background: transparent; padding: 10px 14px; }
.hmdg-card__body .tablenav-pages { color: #64748b; font-size: 13px; }

/* Subtabs for status filter */
.hmdg-subtabs {
    display: inline-flex;
    gap: 2px;
    margin-top: 14px;
    padding: 4px;
    background: #f1f5f9;
    border-radius: 10px;
}
.hmdg-subtab {
    padding: 6px 12px;
    border-radius: 7px;
    font-size: 12px;
    font-weight: 600;
    color: #64748b;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    transition: background 120ms ease, color 120ms ease;
}
.hmdg-subtab:hover { color: #0f172a; }
.hmdg-subtab--active { background: #fff; color: #0f172a; box-shadow: 0 1px 2px rgba(15,23,42,0.08); }
.hmdg-subtab__count {
    background: #e2e8f0;
    color: #334155;
    border-radius: 999px;
    padding: 1px 8px;
    font-size: 11px;
    font-weight: 700;
}
.hmdg-subtab--active .hmdg-subtab__count { background: #312e81; color: #fff; }

/* Pills */
.hmdg-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.02em;
    text-transform: uppercase;
    line-height: 1.5;
}
.hmdg-pill--danger   { background: #fee2e2; color: #991b1b; box-shadow: inset 0 0 0 1px #fecaca; }
.hmdg-pill--warning  { background: #fef3c7; color: #92400e; box-shadow: inset 0 0 0 1px #fde68a; }
.hmdg-pill--info     { background: #e0f2fe; color: #075985; box-shadow: inset 0 0 0 1px #bae6fd; }
.hmdg-pill--muted    { background: #f1f5f9; color: #475569; box-shadow: inset 0 0 0 1px #e2e8f0; }
.hmdg-pill--neutral  { background: #e2e8f0; color: #334155; }
.hmdg-pill--ok       { background: #dcfce7; color: #166534; box-shadow: inset 0 0 0 1px #bbf7d0; }

/* Status chip (quarantine table) */
.hmdg-status {
    display: inline-flex; align-items: center; gap: 8px;
    font-size: 12px; font-weight: 600; color: #334155;
}
.hmdg-status__dot { width: 8px; height: 8px; border-radius: 999px; background: #94a3b8; box-shadow: 0 0 0 3px rgba(148,163,184,0.15); }
.hmdg-status--quarantined .hmdg-status__dot { background: #dc2626; box-shadow: 0 0 0 3px rgba(220,38,38,0.12); }
.hmdg-status--quarantined { color: #991b1b; }
.hmdg-status--deleted .hmdg-status__dot { background: #64748b; box-shadow: 0 0 0 3px rgba(100,116,139,0.15); }
.hmdg-status--deleted { color: #475569; }
.hmdg-status--fp .hmdg-status__dot { background: #16a34a; box-shadow: 0 0 0 3px rgba(22,163,74,0.15); }
.hmdg-status--fp { color: #166534; }
.hmdg-status--flagged .hmdg-status__dot { background: #f59e0b; box-shadow: 0 0 0 3px rgba(245,158,11,0.15); }
.hmdg-status--flagged { color: #92400e; }

/* File code */
.hmdg-file code,
.hmdg-signal,
.hmdg-ip {
    font-family: Menlo, Consolas, "SF Mono", monospace;
    font-size: 12px;
    background: #f1f5f9;
    padding: 3px 8px;
    border-radius: 6px;
    color: #0f172a;
}
.hmdg-ip { background: #ede9fe; color: #4c1d95; }
.hmdg-weight {
    display: inline-block;
    margin-left: 6px;
    padding: 1px 7px;
    font-size: 11px;
    font-weight: 700;
    background: #fee2e2;
    color: #991b1b;
    border-radius: 999px;
}
.hmdg-source { font-size: 12px; color: #64748b; }
.hmdg-muted { color: #94a3b8; }
.hmdg-countdown { font-variant-numeric: tabular-nums; color: #475569; font-size: 13px; }

/* Buttons */
.hmdg-actions { display: flex; gap: 6px; }
.hmdg-btn.button.button-small {
    padding: 3px 12px;
    font-size: 12px;
    font-weight: 600;
    border-radius: 8px;
    border: 1px solid transparent;
    line-height: 1.8;
    height: auto;
}
.hmdg-btn--unlock { background: #312e81; color: #fff; border-color: #312e81; }
.hmdg-btn--unlock:hover, .hmdg-btn--unlock:focus { background: #4338ca; border-color: #4338ca; color: #fff; }
.hmdg-btn--danger { background: #fff; color: #991b1b; border-color: #fca5a5; }
.hmdg-btn--danger:hover, .hmdg-btn--danger:focus { background: #fee2e2; border-color: #f87171; color: #7f1d1d; }
.hmdg-btn--ok { background: #fff; color: #166534; border-color: #86efac; }
.hmdg-btn--ok:hover, .hmdg-btn--ok:focus { background: #dcfce7; border-color: #4ade80; color: #14532d; }

/* Notice */
.hmdg-notice {
    margin: 18px 0 0;
    padding: 12px 18px;
    border-radius: 12px;
    border: 1px solid transparent;
    font-size: 13px;
    font-weight: 500;
}
.hmdg-notice--success { background: #dcfce7; border-color: #86efac; color: #14532d; }
.hmdg-notice--error   { background: #fee2e2; border-color: #fca5a5; color: #7f1d1d; }
.hmdg-notice--warning { background: #fef3c7; border-color: #fde68a; color: #78350f; }

/* Empty state */
.hmdg-empty {
    padding: 48px 20px;
    text-align: center;
    color: #64748b;
}
.hmdg-empty__icon { font-size: 40px; margin-bottom: 12px; filter: grayscale(0.1); }
.hmdg-empty h3 { color: #0f172a; font-size: 18px; margin: 0 0 6px; }
.hmdg-empty p { margin: 0 auto; max-width: 460px; font-size: 13px; line-height: 1.5; }

/* Responsive */
@media (max-width: 960px) {
    .hmdg-hero__inner { flex-direction: column; align-items: flex-start; }
    .hmdg-hero__stats { width: 100%; }
    .hmdg-stat { flex: 1; }
}
</style>
CSS;
    }

    /**
     * @return array<string, int>
     */
    private function quarantineCounts(): array
    {
        if ($this->quarantineCounts !== null) {
            return $this->quarantineCounts;
        }

        $this->quarantineCounts = $this->repository->countByStatuses([
            FindingsRepository::STATUS_QUARANTINED,
            FindingsRepository::STATUS_DELETED,
            FindingsRepository::STATUS_FALSE_POSITIVE,
            FindingsRepository::STATUS_FLAGGED,
        ]);

        return $this->quarantineCounts;
    }
}
