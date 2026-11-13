<?php

declare(strict_types=1);

namespace HMDG\Security\Detection;

use HMDG\Security\Admin\QuarantineService;
use HMDG\Security\SecurityEvent;
use HMDG\Security\Services\AlertService;
use HMDG\Security\Services\LogService;

/**
 * Bridge between (Severity, signals, path) findings and the AlertService.
 *
 * Responsibilities:
 *   - Log every finding regardless of Severity (at the level chosen by
 *     Severity::logLevel()).
 *   - Route Suspicious and HighRisk through AlertService. Its independent
 *     SecurityEvent policy denies email for all current heuristic findings.
 *   - Map Severity onto the correct SecurityEvent case so alert
 *     subjects, default recommendations, and log severity remain
 *     consistent across the plugin.
 *   - Supply the `unique_key` used by AlertService for per-file
 *     dedup (`scan:<path>`).
 *   - Preserve HighRisk auto-quarantine independently of email eligibility.
 *
 * @since 1.4.0
 */
final class AlertDispatcher
{
    /** Module identifier used in log entries. */
    private const MODULE = 'AlertDispatcher';

    /**
     * Optional QuarantineService for v1.5.0 auto-quarantine on
     * HighRisk findings. Nullable so the detection engine keeps
     * working without the admin stack — e.g. during activation or
     * CLI contexts where Plugin::bootAdminOperations() has not run.
     */
    private ?QuarantineService $quarantineService = null;

    /**
     * @param AlertService $alertService Email dispatch service.
     * @param LogService   $logService   Structured logger.
     */
    public function __construct(
        private readonly AlertService $alertService,
        private readonly LogService $logService,
    ) {}

    /**
     * Inject the v1.5.0 QuarantineService. Called by Plugin::bootAdminOperations
     * the first time the admin context boots. Safe to call multiple times —
     * the second call simply overwrites the reference.
     */
    public function setQuarantineService(QuarantineService $service): void
    {
        $this->quarantineService = $service;
    }

    /**
     * Handle a classified finding.
     *
     * @param Severity     $severity     The scorer's verdict.
     * @param string       $absolutePath Absolute path to the scanned file.
     * @param list<Signal> $signals      Raw signals from the detectors.
     * @param string       $source       Identifier for the producing
     *                                   module (e.g. `malware_scanner`
     *                                   or `file_integrity_scan`). Used
     *                                   for rate-limiting keys.
     */
    public function handle(
        Severity $severity,
        string $absolutePath,
        array $signals,
        string $source,
    ): void {
        // Every finding is logged — even Safe, though we keep it at
        // INFO-level silence in practice.
        $logContext = [
            'source'         => $source,
            'file'           => $absolutePath,
            'severity'       => $severity->name,
            'score_tier'     => $severity->value,
            'signal_count'   => count($signals),
            'categories'     => $this->categoryList(signals: $signals),
            'labels'         => $this->labelList(signals: $signals),
        ];

        $this->logService->log(
            severity: $severity->logLevel(),
            module: self::MODULE,
            message: sprintf(
                'Risk classification: %s for %s',
                $severity->emailSubject(),
                $absolutePath,
            ),
            context: $logContext,
        );

        // v1.7.0 — Suspicious / NeedsReview findings do NOT move the
        // file (auto-quarantining borderline detections can break
        // legitimate sites), but we record a flagged row in the admin
        // Quarantine table so operators have a visible review queue
        // regardless of whether the severity emails. Idempotent: the
        // repository's findByPathAndStatus short-circuits duplicates
        // on repeat detections of the same file.
        if (
            ($severity === Severity::Suspicious || $severity === Severity::NeedsReview)
            && $this->quarantineService !== null
        ) {
            $this->quarantineService->flag(
                absolutePath: $absolutePath,
                severity: $severity,
                signals: $signals,
                source: $source,
            );
        }

        // Lower tiers stop here. Keep HighRisk flowing through to the
        // quarantine action even when AlertService declines email.
        if (!$severity->emitsEmail()) {
            return;
        }

        $event   = $this->mapToSecurityEvent(severity: $severity);
        $timestamp = (new \DateTimeImmutable(
            datetime: 'now',
            timezone: new \DateTimeZone(timezone: 'Europe/London'),
        ))->format(format: 'Y-m-d H:i:s T');

        // Pick the worst-signal snippet for the email body. Finding
        // with the single highest weight is the most interesting thing
        // to show in the digest; the full list is already in the log.
        $topSignal = $this->highestWeightSignal(signals: $signals);

        $context = [
            'source'         => $source,
            'file_path'      => $absolutePath,
            'timestamp'      => $timestamp,
            'site_url'       => function_exists('get_site_url') ? get_site_url() : '',
            'severity'       => $severity->emailSubject(),
            'severity_level' => $severity->name,
            'signal_count'   => count($signals),
            'categories'     => implode(', ', $this->categoryList(signals: $signals)),
            'signal_labels'  => implode('; ', $this->labelList(signals: $signals)),
            'recommendation' => $this->recommendation(severity: $severity),
            // Per-file-path dedup key — AlertService suppresses a
            // repeat alert for the same path within 7 days.
            'unique_key'     => 'scan:' . $absolutePath,
            // Severity passed through for downstream consumers (e.g. a
            // future report module) even though AlertService maps onto
            // SecurityEvent::severity() internally.
            'severity_enum'  => $severity->value,
        ];

        if ($topSignal !== null) {
            $context['top_signal_label']    = $topSignal->label;
            $context['top_signal_category'] = $topSignal->category->value;
            $context['top_signal_weight']   = $topSignal->weight;

            if (isset($topSignal->context['line']) && $topSignal->context['line'] !== '') {
                $context['line_number'] = (int) $topSignal->context['line'];
            }

            if (isset($topSignal->context['snippet']) && is_string($topSignal->context['snippet'])) {
                // AlertService already escapes on output; pre-sanitise
                // for defence in depth.
                $context['code_snippet'] = htmlspecialchars(
                    string: $topSignal->context['snippet'],
                    flags: ENT_QUOTES | ENT_SUBSTITUTE,
                    encoding: 'UTF-8',
                );
            }
        }

        $this->alertService->send(
            event: $event,
            context: $context,
            severity: $severity,
        );

        // v1.5.0 — auto-quarantine HighRisk findings. Only HighRisk,
        // never Suspicious. If the QuarantineService is not wired in
        // (admin boot has not run) we just skip; the finding remains
        // logged. The file stays in place and can be actioned on the
        // next admin visit once the system
        // re-detects it.
        if ($severity === Severity::HighRisk && $this->quarantineService !== null) {
            $this->quarantineService->quarantine(
                absolutePath: $absolutePath,
                severity: $severity,
                signals: $signals,
                source: $source,
            );
        }
    }

    /**
     * Map a Severity onto the SecurityEvent that best represents it.
     *
     * v1.4.0 introduces three tier-specific cases (HighRiskTampering,
     * SuspiciousChange, NeedsReviewFinding). Anything below Suspicious
     * never reaches this method (emitsEmail() filters first).
     */
    private function mapToSecurityEvent(Severity $severity): SecurityEvent
    {
        return match ($severity) {
            Severity::HighRisk       => SecurityEvent::HighRiskTampering,
            Severity::Suspicious     => SecurityEvent::SuspiciousChange,
            // Defensive — NeedsReviewFinding should not hit email dispatch
            // under current rules (Severity::NeedsReview->emitsEmail() is
            // false), but if a future tweak changes the threshold this
            // mapping is already correct.
            Severity::NeedsReview    => SecurityEvent::NeedsReviewFinding,
            // Below-threshold severities should never reach this method.
            // Fallback to MalwareDetected preserves backwards-compat with
            // any callers that bypass the emitsEmail() filter.
            default                  => SecurityEvent::MalwareDetected,
        };
    }

    /**
     * Recommendation text for the alert body.
     */
    private function recommendation(Severity $severity): string
    {
        return match ($severity) {
            Severity::HighRisk => 'URGENT: Multi-signal tampering detected. Isolate the file immediately. '
                . 'Take a forensic copy before any modification. Scan the entire install for related infections '
                . 'and review recent file modifications across wp-content/.',
            Severity::Suspicious => 'Review the file manually. Compare it against the canonical plugin/theme '
                . 'distribution. If the change was not intentional, quarantine the file and investigate the source '
                . 'of modification (recent uploads, user activity, FTP logs).',
            Severity::NeedsReview => 'Low-confidence finding. Review the file when convenient. If the file '
                . 'belongs to a legitimate plugin or theme, the finding is most likely benign.',
            default => 'Review the flagged file.',
        };
    }

    /**
     * Unique category names present in the signal set.
     *
     * @param list<Signal> $signals
     *
     * @return list<string>
     */
    private function categoryList(array $signals): array
    {
        $seen = [];

        foreach ($signals as $signal) {
            if (!$signal instanceof Signal) {
                continue;
            }
            $seen[$signal->category->value] = true;
        }

        return array_keys($seen);
    }

    /**
     * Signal labels joined for log/email context.
     *
     * @param list<Signal> $signals
     *
     * @return list<string>
     */
    private function labelList(array $signals): array
    {
        $labels = [];

        foreach ($signals as $signal) {
            if (!$signal instanceof Signal) {
                continue;
            }
            $labels[] = $signal->label;
        }

        return $labels;
    }

    /**
     * Return the Signal with the greatest weight in the supplied list.
     *
     * @param list<Signal> $signals
     */
    private function highestWeightSignal(array $signals): ?Signal
    {
        $top = null;

        foreach ($signals as $signal) {
            if (!$signal instanceof Signal) {
                continue;
            }
            if ($top === null || $signal->weight > $top->weight) {
                $top = $signal;
            }
        }

        return $top;
    }
}
