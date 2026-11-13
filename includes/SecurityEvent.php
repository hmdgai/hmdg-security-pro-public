<?php

declare(strict_types=1);

namespace HMDG\Security;

/**
 * Enumeration of all security event types tracked by the plugin.
 *
 * Each case maps to an alert severity and human-readable label used
 * by AlertService for email notifications and LogService for file logging.
 *
 * v1.4.0: three tier-specific cases (HighRiskTampering, SuspiciousChange,
 * NeedsReviewFinding) replace the binary MalwareDetected classification for
 * scanner output. The MalwareDetected case is retained for backwards
 * compatibility with callers that predate the detection engine; new code
 * should dispatch one of the severity-specific cases via AlertDispatcher.
 */
enum SecurityEvent: string
{
    case LoginFailed = 'login_failed';
    case LoginLockout = 'login_lockout';
    // Kept after SpamProtection module was removed in 1.3.0 — DiviSecurity
    // and ElementorSecurity still dispatch this event when their builder-
    // level form checks detect spam. Removing the case would fatal both
    // those modules on every spam detection. See CHANGELOG 1.3.0.
    case SpamDetected = 'spam_detected';
    case FileModified = 'file_modified';
    /**
     * @deprecated 1.4.0 Prefer HighRiskTampering / SuspiciousChange /
     *             NeedsReviewFinding. Retained for backwards compatibility
     *             and for the historical uploads-PHP alert path.
     */
    case MalwareDetected = 'malware_detected';
    case NewAdminUser = 'new_admin_user';
    case RoleEscalation = 'role_escalation';
    case UserDeleted = 'user_deleted';
    case SuspiciousUpload = 'suspicious_upload';
    case BuilderAnomalyDetected = 'builder_anomaly_detected';

    /** v1.4.0 — highest-severity scan finding (multi-signal, multi-category). */
    case HighRiskTampering = 'high_risk_tampering';

    /** v1.4.0 — mid-severity scan finding requiring operator review. */
    case SuspiciousChange = 'suspicious_change';

    /** v1.4.0 — low-severity scan finding surfaced for awareness. */
    case NeedsReviewFinding = 'needs_review_finding';

    /**
     * Alert severity level for email subjects and log entries.
     */
    public function severity(): string
    {
        return match ($this) {
            self::MalwareDetected,
            self::RoleEscalation,
            self::SuspiciousUpload,
            self::HighRiskTampering => 'CRITICAL',

            self::LoginLockout,
            self::FileModified,
            self::NewAdminUser,
            self::UserDeleted,
            self::BuilderAnomalyDetected,
            self::SuspiciousChange => 'WARNING',

            self::LoginFailed,
            self::SpamDetected,
            self::NeedsReviewFinding => 'INFO',
        };
    }

    /**
     * Whether this event type should produce an operator email.
     *
     * Only independently verified malware may email. No current event
     * has a producer that establishes that proof: HighRiskTampering is
     * heuristic, and the legacy MalwareDetected path reports PHP in
     * uploads without confirming malware. All current events therefore
     * remain silent, regardless of severity or caller-supplied context.
     *
     * This gates email only. Callers retain detection, logging, dashboard
     * records and quarantine behaviour. A future verified-malware producer
     * needs a separately reviewed event and evidence contract before it
     * can be enabled here; a confirmation flag is not sufficient.
     *
     * Exhaustive match: a new case must be reviewed here. An omitted case
     * throws UnhandledMatchError when evaluated instead of enabling mail.
     *
     * @since 1.7.0
     */
    public function emitsEmail(): bool
    {
        return match ($this) {
            // Heuristics, baseline drift and uploads PHP are not proof.
            self::HighRiskTampering,
            self::SuspiciousChange,
            self::NeedsReviewFinding,
            self::MalwareDetected,
            self::SuspiciousUpload,
            self::FileModified,

            // Other security events remain silent as before.
            self::LoginFailed,
            self::LoginLockout,
            self::SpamDetected,
            self::NewAdminUser,
            self::RoleEscalation,
            self::UserDeleted,
            self::BuilderAnomalyDetected => false,
        };
    }

    /**
     * Human-readable label for email subjects.
     */
    public function label(): string
    {
        return match ($this) {
            self::LoginFailed => 'Failed Login Attempt',
            self::LoginLockout => 'Login Lockout Triggered',
            self::SpamDetected => 'Spam Submission Blocked',
            self::FileModified => 'Core File Modified',
            self::MalwareDetected => 'Malware Detected',
            self::NewAdminUser => 'New Administrator Created',
            self::RoleEscalation => 'User Role Escalation',
            self::UserDeleted => 'User Account Deleted',
            self::SuspiciousUpload => 'Suspicious File Upload',
            self::BuilderAnomalyDetected => 'Page Builder Anomaly',
            self::HighRiskTampering => 'High Risk Tampering',
            self::SuspiciousChange => 'Suspicious Change',
            self::NeedsReviewFinding => 'Needs Review',
        };
    }
}
