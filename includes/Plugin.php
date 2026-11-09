<?php

declare(strict_types=1);

namespace HMDG\Security;

use HMDG\Security\Admin\AdminActions;
use HMDG\Security\Admin\AdminPage;
use HMDG\Security\Admin\FindingsRepository;
use HMDG\Security\Admin\LockoutLogRepository;
use HMDG\Security\Admin\QuarantineService;
use HMDG\Security\Admin\Schema;
use HMDG\Security\Compatibility\HmdgHelpersCompat;
use HMDG\Security\Detection\AlertDispatcher;
use HMDG\Security\Detection\CoreChecksumClient;
use HMDG\Security\Detection\PathClassifier;
use HMDG\Security\Detection\RiskScorer;
use HMDG\Security\Detection\SignalDetectors\Baseline;
use HMDG\Security\Detection\SignalDetectors\CodeContext;
use HMDG\Security\Detection\SignalDetectors\Obfuscation;
use HMDG\Security\Detection\SignalDetectors\PathAnomaly;
use HMDG\Security\Detection\SignalDetectors\Persistence;
use HMDG\Security\Detection\SignalDetectors\RemoteExec;
use HMDG\Security\Detection\UpdateCorrelator;
use HMDG\Security\Modules\ConflictCleaner;
use HMDG\Security\Modules\DatabaseCleanup;
use HMDG\Security\Modules\DiviSecurity;
use HMDG\Security\Modules\ElementorSecurity;
use HMDG\Security\Modules\FileIntegrity;
use HMDG\Security\Modules\Hardening;
use HMDG\Security\Modules\Headers;
use HMDG\Security\Modules\LoginProtection;
use HMDG\Security\Modules\MalwareScanner;
use HMDG\Security\Modules\UpdateMonitor;
use HMDG\Security\Modules\UserMonitor;
use HMDG\Security\Services\AlertService;
use HMDG\Security\Services\BuilderDetectionService;
use HMDG\Security\Services\CronService;
use HMDG\Security\Services\LogService;
use HMDG\Security\Services\ObjectCacheService;
use HMDG\Security\Services\ReleaseUpdater;

/**
 * Main orchestrator — wires services and modules based on request context.
 *
 * Boot strategy is context-aware. Each module is loaded only on requests
 * where its hooks can actually fire. Front-end visitor requests get just
 * Headers and a slim Hardening pass; login requests get LoginProtection;
 * admin requests get UserMonitor; AJAX requests to builder endpoints get
 * ElementorSecurity / DiviSecurity; cron requests get the scheduled
 * scanners. Nothing else loads.
 *
 * This is the single biggest performance lever in the plugin.
 */
final class Plugin
{
    private readonly SecurityConfig $config;
    private readonly BuilderDetectionService $builderDetection;
    private readonly ObjectCacheService $cacheService;
    private readonly LogService $logService;
    private readonly AlertService $alertService;
    private readonly CronService $cronService;

    // v1.4.0 detection engine
    private readonly PathClassifier $pathClassifier;
    private readonly UpdateCorrelator $updateCorrelator;
    private readonly CoreChecksumClient $coreChecksumClient;
    private readonly RiskScorer $riskScorer;
    private readonly AlertDispatcher $alertDispatcher;
    private readonly Obfuscation $obfuscationDetector;
    private readonly CodeContext $codeContextDetector;
    private readonly RemoteExec $remoteExecDetector;
    private readonly Persistence $persistenceDetector;
    private readonly PathAnomaly $pathAnomalyDetector;
    private readonly Baseline $baselineDetector;
    private ?FindingsRepository $findingsRepository = null;
    private ?LockoutLogRepository $lockoutLogRepository = null;
    private ?QuarantineService $quarantineService = null;

    public function __construct()
    {
        $this->config = new SecurityConfig();
        $this->builderDetection = new BuilderDetectionService();
        $this->cacheService = new ObjectCacheService();
        $this->logService = new LogService($this->builderDetection);
        $this->alertService = new AlertService(
            config: $this->config,
            logService: $this->logService,
            builderDetection: $this->builderDetection,
            cacheService: $this->cacheService,
        );
        $this->cronService = new CronService(
            logService: $this->logService,
            cacheService: $this->cacheService,
        );

        // v1.4.0 detection engine. Services are stateless (PathClassifier,
        // RiskScorer, dispatchers) or wrap stateless caches/HTTP clients
        // — construction is cheap. We instantiate them unconditionally
        // here so the modules that consume them (MalwareScanner +
        // FileIntegrity) can always rely on them being available.
        $this->pathClassifier     = new PathClassifier();
        $this->updateCorrelator   = new UpdateCorrelator(cacheService: $this->cacheService);
        $this->coreChecksumClient = new CoreChecksumClient(
            cacheService: $this->cacheService,
            logService:   $this->logService,
        );
        $this->riskScorer = new RiskScorer(
            pathClassifier:     $this->pathClassifier,
            updateCorrelator:   $this->updateCorrelator,
            coreChecksumClient: $this->coreChecksumClient,
        );
        $this->alertDispatcher = new AlertDispatcher(
            alertService: $this->alertService,
            logService:   $this->logService,
        );
        $this->obfuscationDetector = new Obfuscation(
            base64MinLength: $this->config->malwareBase64MinLength,
        );
        $this->codeContextDetector = new CodeContext();
        $this->remoteExecDetector  = new RemoteExec(
            legitimateDomains: $this->config->legitimateDomains,
        );
        $this->persistenceDetector = new Persistence();
        $this->pathAnomalyDetector = new PathAnomaly(
            coreChecksumClient: $this->coreChecksumClient,
        );
        $this->baselineDetector = new Baseline();
    }

    /**
     * Public accessor for the CronService instance.
     *
     * Used by the activation/deactivation hooks in hmdg-security-pro.php so
     * they can drive the same service that runtime code uses, without
     * re-instantiating it.
     */
    public function cronService(): CronService
    {
        return $this->cronService;
    }

    /**
     * Boot all modules appropriate for the current request context.
     *
     * The boot sequence has a deliberate order:
     *   1. Custom cron intervals — must be registered before WP reads
     *      `wp_get_schedules()` for any subsequent `wp_schedule_event` call.
     *      One `add_filter` call, effectively free.
     *   2. Scheduled-event registration sweep — idempotent, static-flagged.
     *      Runs real work only on the first call per PHP worker lifetime.
     *   3. Cron callback binding — wires hook names to module methods, plus
     *      the report placeholders. GATED on request context: only binds
     *      in admin / cron / CLI, where a cron hook can actually fire.
     *      Anonymous front-end GETs skip this, avoiding three heavy module
     *      instantiations (FileIntegrity, MalwareScanner, DatabaseCleanup)
     *      per page load.
     *   4. Boot-time logging + Flywheel admin notice (admin context only).
     *   5. The rest of the module boots branch on request context.
     *
     * On WP-CLI we still register cron events (so `wp cron event run`
     * works) but skip the HTTP-only modules.
     */
    public function boot(): void
    {
        // Register before CLI/cron early returns. Anonymous visitors never
        // instantiate the updater, read its cache, or call the release API.
        if ($this->shouldBindCronCallbacks()) {
            (new ReleaseUpdater($this->cacheService, $this->logService))->register();
        }

        // Schema migration — handles in-place upgrades where the activation
        // hook does not re-fire. Guarded to admin/cron/CLI so anonymous
        // front-end requests never touch options or DDL.
        if ($this->shouldBindCronCallbacks()) {
            $installedSchema = get_option(Schema::OPTION_VERSION, '0');
            if (version_compare((string) $installedSchema, Schema::VERSION, '<')) {
                Schema::install();
            }
        }

        // ── 1–2. Cron interval + event registration run in every context.
        // `registerCustomIntervals` is a single `add_filter` call.
        // `registerScheduledEvents` is static-guarded so it only does real
        // work once per PHP worker's lifetime — on a warm worker, it's a
        // single boolean check.
        $this->cronService->registerCustomIntervals();
        $this->cronService->registerScheduledEvents();

        // ── 3. Cron callback binding — context-gated.
        //
        // Instantiating FileIntegrity, MalwareScanner, and DatabaseCleanup
        // is the single most expensive thing this plugin does per request:
        // three final classes with six injected services each, plus their
        // base64-pattern compilation etc. On an anonymous front-end GET
        // that cost is pure waste — `add_action` registrations on cron
        // hook names never fire unless the current request is a cron run.
        //
        // Gate on `shouldBindCronCallbacks()` — true for:
        //   - `wp_doing_cron()`: wp-cron.php sub-requests (WP Engine server
        //     cron, Flywheel visitor-triggered cron, anything DOING_CRON).
        //   - `WP_CLI`: `wp cron event run <hook>` expects callbacks bound.
        //   - `is_admin()`: covers admin-ajax.php triggers and manual
        //     "Run now" calls from tools like WP Crontrol. Also a safety
        //     net for admin flows that fire cron synchronously.
        //
        // Front-end visitors (the 95%+ case on a typical site) skip this
        // block entirely.
        if ($this->shouldBindCronCallbacks()) {
            $this->bindCronCallbacks();
            // Automatic/CLI upgrades also need the post-update partial
            // baseline refresh. Register before both context early returns.
            $this->bootUpdateMonitor();
        }

        // CLI bypass — registration above is enough for `wp cron event run`,
        // but we never boot HTTP-only modules.
        if ($this->isCli()) {
            return;
        }

        // 5. Boot logging — throttled, only one file write per hour at most.
        $this->cronService->logEnvironmentOnBoot();

        // Cron context — only scheduled scanners (callbacks already bound).
        // Before returning, log HMDG Helpers compatibility status so every
        // cron run has a fresh snapshot in the log. Restricted to cron
        // context (one write per cron invocation ≈ once per day on WP Engine
        // server cron) so admin page navigation does not spam the log.
        if (wp_doing_cron()) {
            $this->logService->info(
                module: 'HmdgHelpersCompat',
                message: 'HMDG Helpers compatibility status',
                context: HmdgHelpersCompat::get_conflict_report(),
            );
            return;
        }

        $isAdmin = is_admin();
        $isAjax = wp_doing_ajax();
        $isRest = defined('REST_REQUEST') && REST_REQUEST;
        $isLogin = $this->isLoginContext();

        // Flywheel admin notice — admin-only, the single UI surface.
        if ($isAdmin) {
            $this->cronService->registerAdminNotice();

            // ConflictCleaner's one-shot admin notice. Static callable so
            // no ConflictCleaner instance needs to be kept alive across
            // admin requests. The handler reads a transient set by the
            // activation-time cleanup and early-returns when it is empty
            // (the steady-state case on every admin page load after the
            // first one following activation). See
            // includes/Modules/ConflictCleaner.php for the safety posture.
            add_action('admin_notices', [ConflictCleaner::class, 'show_admin_notice']);

        }

        // v1.5.0 operations UI — admin only, never on anonymous
        // front-end. Gates AdminPage / AdminActions registration on
        // is_admin() so visitor GETs carry zero instantiation cost.
        if ($isAdmin) {
            $this->bootAdminOperations();
        }

        // Headers — sent on real browser requests only (not AJAX/REST data calls)
        if (!$isAjax && !$isRest) {
            $this->bootHeaders();
        }

        // Hardening — broad protections needed across browser-facing surfaces
        // (skipped for AJAX/REST data calls where its hooks are no-ops)
        if (!$isAjax && !$isRest) {
            $this->bootHardening();
        } elseif ($isRest) {
            // REST needs only the user-enumeration filter from Hardening,
            // which Hardening installs as part of its full registration.
            // Cost is acceptable; the alternative is splitting Hardening.
            $this->bootHardening();
        }

        // Login protection — login pages and XML-RPC, plus any POST that looks
        // like an authentication attempt (covers WPS Hide Login etc.)
        if ($isLogin) {
            $this->bootLoginProtection();
        }

        // SpamProtection module removed in 1.3.0 — it declared
        // injectHoneypotWpforms(string $content) but WPForms'
        // wpforms_display_submit_before hook passes an array, fatally
        // typed-error-ing on every form render. All HMDG client sites
        // use Google reCAPTCHA v3 at the form level, and the builder
        // modules (DiviSecurity, ElementorSecurity) still dispatch
        // `SecurityEvent::SpamDetected` for their own form-level checks,
        // so removing the module does not lose spam-event telemetry.

        // Builder-specific modules — only on contexts where builder hooks fire.
        // Builder upload/form/JSON hooks run on front-end, AJAX, and REST.
        if (!$isAdmin || $isAjax || $isRest) {
            if ($this->builderDetection->isElementorInstalled()) {
                $this->bootElementorSecurity();
            }
            if ($this->builderDetection->isDiviInstalled()) {
                $this->bootDiviSecurity();
            }
        } elseif ($isAdmin) {
            // In admin: still need ElementorSecurity for upload validation
            // (media library uploads) and DiviSecurity for outbound HTTP audit.
            if ($this->builderDetection->isElementorInstalled()) {
                $this->bootElementorSecurity();
            }
            if ($this->builderDetection->isDiviInstalled()) {
                $this->bootDiviSecurity();
            }
        }

        // User monitor — only contexts where user lifecycle hooks can fire.
        // user_register, set_user_role, delete_user etc. all originate from
        // admin actions, REST writes, or registration POSTs.
        if ($isAdmin || $isRest || $isAjax || $isLogin) {
            $this->bootUserMonitor();
        }
    }

    private function bootHardening(): void
    {
        new Hardening(
            config: $this->config,
            builderDetection: $this->builderDetection,
            logService: $this->logService,
        );
    }

    private function bootHeaders(): void
    {
        new Headers(
            config: $this->config,
            builderDetection: $this->builderDetection,
        );
    }

    private function bootLoginProtection(): void
    {
        new LoginProtection(
            config: $this->config,
            cacheService: $this->cacheService,
            alertService: $this->alertService,
            logService: $this->logService,
            builderDetection: $this->builderDetection,
            lockoutLog: $this->lockoutLogRepository(),
        );
    }

    private function bootElementorSecurity(): void
    {
        new ElementorSecurity(
            config: $this->config,
            alertService: $this->alertService,
            logService: $this->logService,
            builderDetection: $this->builderDetection,
        );
    }

    private function bootDiviSecurity(): void
    {
        new DiviSecurity(
            config: $this->config,
            alertService: $this->alertService,
            logService: $this->logService,
            builderDetection: $this->builderDetection,
        );
    }

    private function bootUserMonitor(): void
    {
        new UserMonitor(
            config: $this->config,
            alertService: $this->alertService,
            logService: $this->logService,
        );
    }

    /**
     * v1.5.0 operations UI — registers the top-level HMDG Security
     * admin page and its admin-post action handlers. Admin-only by
     * construction (this method is called only inside the is_admin
     * branch of boot()). Every class inside `HMDG\Security\Admin`
     * is read-only at class level; registration work happens via
     * add_action callbacks and runs per-request.
     */
    private function bootAdminOperations(): void
    {
        $repository = $this->findingsRepository();
        $quarantineService = $this->makeQuarantineService();

        // Make sure the quarantine directory + .htaccess exist. Cheap;
        // one is_dir() check on cached inode in the common case.
        $quarantineService->ensureDirectory();

        $adminPage = new AdminPage(
            cacheService: $this->cacheService,
            repository: $repository,
            lockoutLogRepo: $this->lockoutLogRepository(),
            config: $this->config,
        );
        $adminPage->register();

        // Action handlers need a LoginProtection instance to reuse its
        // unlock() primitive. This is NOT the login-path registration —
        // we never call ->register() here — so no duplicate login hooks fire.
        $loginProtection = new LoginProtection(
            config: $this->config,
            cacheService: $this->cacheService,
            alertService: $this->alertService,
            logService: $this->logService,
            builderDetection: $this->builderDetection,
            lockoutLog: $this->lockoutLogRepository(),
        );

        $adminActions = new AdminActions(
            quarantineService: $quarantineService,
            repository: $repository,
            lockoutLog: $this->lockoutLogRepository(),
            cacheService: $this->cacheService,
            logService: $this->logService,
            loginProtection: $loginProtection,
        );
        $adminActions->register();
    }

    private function findingsRepository(): FindingsRepository
    {
        return $this->findingsRepository ??= new FindingsRepository(
            cacheService: $this->cacheService,
        );
    }

    private function makeQuarantineService(): QuarantineService
    {
        if ($this->quarantineService !== null) {
            return $this->quarantineService;
        }

        $this->quarantineService = new QuarantineService(
            repository: $this->findingsRepository(),
            logService: $this->logService,
        );

        // Wire quarantine into the already-instantiated dispatcher so
        // HighRisk findings are actioned in cron/admin/CLI scan paths.
        $this->alertDispatcher->setQuarantineService($this->quarantineService);

        return $this->quarantineService;
    }

    private function lockoutLogRepository(): LockoutLogRepository
    {
        global $wpdb;

        return $this->lockoutLogRepository ??= new LockoutLogRepository(
            wpdb: $wpdb,
            table: \HMDG\Security\Admin\Schema::lockoutLogTableName(),
        );
    }

    /**
     * Instantiate and register UpdateMonitor.
     *
     * Creates a dedicated FileIntegrity instance so that UpdateMonitor's
     * partial-rebaseline calls work regardless of whether the cron
     * callback binding path has also created one (it typically has not,
     * since rebaseline runs in the same admin request as the update
     * completion — not in a cron worker). The FileIntegrity instance
     * here is only used for file-hashing and checksum-file I/O; no cron
     * locks acquired, no scanning work triggered.
     */
    private function bootUpdateMonitor(): void
    {
        $this->makeQuarantineService();

        $fileIntegrity = new FileIntegrity(
            config: $this->config,
            alertService: $this->alertService,
            logService: $this->logService,
            builderDetection: $this->builderDetection,
            cacheService: $this->cacheService,
            cronService: $this->cronService,
            riskScorer: $this->riskScorer,
            alertDispatcher: $this->alertDispatcher,
            baselineDetector: $this->baselineDetector,
            pathAnomalyDetector: $this->pathAnomalyDetector,
            obfuscationDetector: $this->obfuscationDetector,
            codeContextDetector: $this->codeContextDetector,
            remoteExecDetector: $this->remoteExecDetector,
            persistenceDetector: $this->persistenceDetector,
        );

        $updateMonitor = new UpdateMonitor(
            logService: $this->logService,
            cacheService: $this->cacheService,
            config: $this->config,
            fileIntegrity: $fileIntegrity,
        );

        $updateMonitor->register();
    }

    /**
     * Wire cron hook names to module callbacks.
     *
     * Called only when `shouldBindCronCallbacks()` returns true — that is,
     * in admin, cron, or CLI contexts where a cron hook can actually fire.
     * Anonymous front-end requests skip this entire method to avoid the
     * cost of instantiating FileIntegrity, MalwareScanner, and
     * DatabaseCleanup purely to register `add_action` hooks that would
     * never fire in that context.
     *
     * The callbacks themselves enforce `wp_doing_cron()` / `WP_CLI` guards,
     * so the callback-level defence-in-depth is unchanged — a misrouted
     * direct `do_action()` in an inappropriate context still cannot run
     * the scan work.
     *
     * Module instances are created here (not earlier) so they only exist
     * when the cron callback might actually run.
     */
    private function bindCronCallbacks(): void
    {
        $this->makeQuarantineService();

        $fileIntegrity = new FileIntegrity(
            config: $this->config,
            alertService: $this->alertService,
            logService: $this->logService,
            builderDetection: $this->builderDetection,
            cacheService: $this->cacheService,
            cronService: $this->cronService,
            riskScorer: $this->riskScorer,
            alertDispatcher: $this->alertDispatcher,
            baselineDetector: $this->baselineDetector,
            pathAnomalyDetector: $this->pathAnomalyDetector,
            obfuscationDetector: $this->obfuscationDetector,
            codeContextDetector: $this->codeContextDetector,
            remoteExecDetector: $this->remoteExecDetector,
            persistenceDetector: $this->persistenceDetector,
        );

        // MalwareScanner v1.4.0: receives the full detection stack.
        // The fileIntegrity dependency is kept for compatibility with
        // any leftover wasRecentlyUpdated() call paths, but the
        // authoritative trusted-update short-circuit now lives in
        // RiskScorer via UpdateCorrelator.
        $malwareScanner = new MalwareScanner(
            config: $this->config,
            logService: $this->logService,
            builderDetection: $this->builderDetection,
            cacheService: $this->cacheService,
            cronService: $this->cronService,
            fileIntegrity: $fileIntegrity,
            riskScorer: $this->riskScorer,
            alertDispatcher: $this->alertDispatcher,
            obfuscationDetector: $this->obfuscationDetector,
            codeContextDetector: $this->codeContextDetector,
            remoteExecDetector: $this->remoteExecDetector,
            persistenceDetector: $this->persistenceDetector,
        );

        $databaseCleanup = new DatabaseCleanup(
            config: $this->config,
            logService: $this->logService,
            builderDetection: $this->builderDetection,
            cacheService: $this->cacheService,
            cronService: $this->cronService,
            lockoutLog: $this->lockoutLogRepository(),
        );

        add_action(CronService::HOOK_INTEGRITY, [$fileIntegrity, 'runScan'], 10, 0);
        add_action(CronService::HOOK_SCAN_BATCH, [$fileIntegrity, 'runScan'], 10, 0);

        add_action(CronService::HOOK_MALWARE, [$malwareScanner, 'runScan'], 10, 0);
        add_action(CronService::HOOK_MALWARE_BATCH, [$malwareScanner, 'runScan'], 10, 0);

        add_action(CronService::HOOK_CLEANUP, [$databaseCleanup, 'runCleanup'], 10, 0);

        // Daily and weekly report placeholders — they log a 'last run'
        // timestamp + dump the current cron health snapshot. A future
        // dedicated report module can unhook these and bind richer ones.
        $this->cronService->bindReportPlaceholders();
    }

    /**
     * Detect whether the current request targets a login flow.
     *
     * Uses $pagenow as the authoritative WordPress signal for wp-login.php
     * (set by WP regardless of the request URI), and SCRIPT_FILENAME as a
     * belt-and-braces fallback for early hooks. Also boots on POST requests
     * carrying classic login fields (`log` + `pwd` or `wp-submit`) so that
     * custom login URL plugins (WPS Hide Login, Perfmatters, iThemes) do
     * not bypass rate limiting — a CRITICAL gap in the original code.
     *
     * @security A previous implementation used str_contains() on REQUEST_URI
     *   and could be both false-triggered (?foo=wp-login.php) and bypassed
     *   (custom login URLs). Replaced with $pagenow + SCRIPT_FILENAME +
     *   POST-shape detection.
     */
    private function isLoginContext(): bool
    {
        // XML-RPC requests authenticate via XML-RPC body
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
            return true;
        }

        $method = $_SERVER['REQUEST_METHOD'] ?? '';
        if ($method !== 'POST') {
            return false;
        }

        // $pagenow is set by WordPress in wp-settings.php during plugins_loaded
        // (see wp-includes/vars.php). It reflects the actual front controller
        // file regardless of the request URI string.
        global $pagenow;
        if (isset($pagenow) && $pagenow === 'wp-login.php') {
            return true;
        }

        // Fallback: SCRIPT_FILENAME points at the resolved PHP file on disk.
        // This catches cases where $pagenow has not yet been set at our hook.
        $scriptFilename = $_SERVER['SCRIPT_FILENAME'] ?? '';
        if (is_string($scriptFilename) && $scriptFilename !== '') {
            $basename = basename($scriptFilename);
            if ($basename === 'wp-login.php' || $basename === 'wp-signup.php') {
                return true;
            }
        }

        // POST shape: login forms post `log` + `pwd` (and usually `wp-submit`).
        // This covers custom login URL plugins that route to wp-login.php
        // internally without exposing the filename in REQUEST_URI.
        // We cannot use isset() on $_POST for nonce safety here — we are not
        // verifying authentication, only deciding whether to register hooks.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- shape detection only
        if (isset($_POST['log'], $_POST['pwd'])) {
            return true;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- shape detection only
        if (isset($_POST['wp-submit'])) {
            return true;
        }

        return false;
    }

    private function isCli(): bool
    {
        return defined('WP_CLI') && WP_CLI;
    }

    /**
     * Whether the current request context can actually fire a cron hook.
     *
     * Used to gate `bindCronCallbacks()`. True only when one of the three
     * cron-eligible contexts is active:
     *
     *   - `wp_doing_cron()` — wp-cron.php sub-request. Set by the core
     *     `DOING_CRON` constant during cron execution, regardless of
     *     whether cron was triggered by WP Engine server cron, Flywheel
     *     visitor-triggered spawn, an external scheduler, or manual POST.
     *   - `WP_CLI` — command-line context. `wp cron event run <hook>`
     *     expects callbacks to be bound before it invokes the hook.
     *   - `is_admin()` — any `/wp-admin/` request, including admin-ajax.
     *     Covers manual "Run now" triggers from cron-management plugins
     *     (WP Crontrol and similar) and any admin flow that synchronously
     *     fires a cron hook via `do_action()`.
     *
     * Returns false for anonymous front-end GETs, REST requests from
     * logged-out users, and AJAX to public endpoints — none of which can
     * legitimately fire a cron hook. Skipping the binding in these cases
     * removes three module class instantiations from every affected
     * request — the 95%+ case on a visitor-heavy site.
     */
    private function shouldBindCronCallbacks(): bool
    {
        return wp_doing_cron() || $this->isCli() || is_admin();
    }
}
