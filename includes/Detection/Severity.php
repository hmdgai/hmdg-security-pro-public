<?php

declare(strict_types=1);

namespace HMDG\Security\Detection;

/**
 * Severity levels emitted by the risk scorer.
 *
 * Replaces the binary MalwareDetected / Not-Malware classification with a
 * six-level ladder. Each level maps to a distinct operator-facing outcome:
 *
 *   - Safe            : No signals, or confirmed-good baseline (e.g. wp.org
 *                       checksum match). No log, no email.
 *   - ExpectedUpdate  : Short-circuit via trusted-update window. Logged at
 *                       INFO; no email. Used when UpdateMonitor has recently
 *                       marked the file's ancestor directory as updated.
 *   - Informational   : Weakest possible signal (score 10-19). Logged at
 *                       INFO; no email. Examples: a file removed from
 *                       baseline with no corroborating category signal.
 *   - NeedsReview     : Score 20-39. Logged at WARNING; no email. Typically
 *                       a single-category hit on a low-weight signal.
 *   - Suspicious      : Score 40-69 OR (score >= 70 on a low-risk path
 *                       without the HighRisk quorum). Logged at WARNING;
 *                       flagged for operator review. No email under the
 *                       current SecurityEvent policy.
 *   - HighRisk        : Score >= 70 with >= 2 categories AND (if LowRisk
 *                       path) the escalation quorum. Logged at CRITICAL;
 *                       flagged for operator review without file movement. No email
 *                       under the current SecurityEvent policy.
 *
 * @since 1.4.0
 */
enum Severity: int
{
    case Safe           = 0;
    case ExpectedUpdate = 10;
    case Informational  = 20;
    case NeedsReview    = 30;
    case Suspicious     = 40;
    case HighRisk       = 50;

    /**
     * Whether this severity reaches the dispatcher's escalation path.
     *
     * Historical name: Suspicious and HighRisk reach AlertService, whose
     * separate SecurityEvent policy denies every current event. Flagging
     * happens independently before this gate; no tier automatically moves files.
     */
    public function emitsEmail(): bool
    {
        return $this->value >= self::Suspicious->value;
    }

    /**
     * Whether this severity is the critical-escalation tier.
     *
     * If the SecurityEvent policy permits delivery, HighRisk bypasses the
     * AlertService global hourly cap. This never overrides event policy.
     */
    public function isCritical(): bool
    {
        return $this === self::HighRisk;
    }

    /**
     * Log-level string suitable for LogService::log()'s $severity parameter.
     *
     * LogService accepts 'CRITICAL', 'WARNING', 'INFO'. Severity maps
     * onto that three-value space as follows:
     *   - HighRisk                                         -> CRITICAL
     *   - Suspicious, NeedsReview                          -> WARNING
     *   - Safe, ExpectedUpdate, Informational              -> INFO
     */
    public function logLevel(): string
    {
        return match ($this) {
            self::HighRisk                         => 'CRITICAL',
            self::Suspicious, self::NeedsReview    => 'WARNING',
            self::Safe,
            self::ExpectedUpdate,
            self::Informational                    => 'INFO',
        };
    }

    /**
     * Human-readable subject label used in the alert email subject line.
     *
     * Replaces the old hardcoded "Malware Detected" label with a tier-
     * specific phrase so the operator can triage the inbox at a glance.
     */
    public function emailSubject(): string
    {
        return match ($this) {
            self::HighRisk       => 'High Risk Tampering',
            self::Suspicious     => 'Suspicious Change',
            self::NeedsReview    => 'Needs Review',
            self::Informational  => 'Informational Finding',
            self::ExpectedUpdate => 'Expected Update',
            self::Safe           => 'Safe',
        };
    }
}
