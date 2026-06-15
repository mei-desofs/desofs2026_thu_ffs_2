package com.kryptos.shared.dataprotection;

import lombok.Getter;

@Getter
public enum DataClassification {

    PUBLIC(
            "Public",
            "Non-sensitive data that can be freely disclosed without harm. Includes data that is intentionally public or carries no risk if exposed.",
            false,
            false,
            false,
            "No retention limit; can be disposed of as needed."
    ),
    INTERNAL(
            "Internal",
            "Data intended for internal use. While not highly sensitive, disclosure could provide useful information to an attacker. Examples: usernames, email addresses, role assignments.",
            false,
            true,
            true,
            "Retain for the lifetime of the user account; delete upon account closure."
    ),
    CONFIDENTIAL(
            "Confidential",
            "Sensitive data that requires protection at rest and in transit. Exposure could cause moderate harm. Includes data that is only encoded (Base64, JWT plaintext payload) and therefore easily decoded. Examples: encrypted credential passwords, JWT tokens, 2FA codes, password reset tokens, audit details.",
            true,
            true,
            true,
            "Retain only as long as necessary for operational purposes; purge securely upon expiry or revocation."
    ),
    RESTRICTED(
            "Restricted",
            "Highly sensitive data that requires the highest level of protection. Exposure could cause severe harm and regulatory penalties. Examples: encryption keys, HMAC secrets, plaintext password hashes (Argon2), database credentials, previous encryption secrets.",
            true,
            true,
            true,
            "Minimize retention; rotate regularly; destroy securely with cryptographic erasure when no longer needed."
    );

    private final String displayName;
    private final String description;
    private final boolean requiresEncryptionAtRest;
    private final boolean requiresEncryptionInTransit;
    private final boolean requiresStrictAccessControl;
    private final String retentionGuidance;

    DataClassification(String displayName, String description,
                       boolean requiresEncryptionAtRest, boolean requiresEncryptionInTransit,
                       boolean requiresStrictAccessControl, String retentionGuidance) {
        this.displayName = displayName;
        this.description = description;
        this.requiresEncryptionAtRest = requiresEncryptionAtRest;
        this.requiresEncryptionInTransit = requiresEncryptionInTransit;
        this.requiresStrictAccessControl = requiresStrictAccessControl;
        this.retentionGuidance = retentionGuidance;
    }

    public boolean isAtLeast(DataClassification other) {
        return this.ordinal() >= other.ordinal();
    }
}
