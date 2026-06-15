package com.kryptos.shared.dataprotection;

import lombok.Getter;

import static com.kryptos.shared.dataprotection.DataClassification.*;

@Getter
public enum SensitiveDataElement {

    // ── User domain ──────────────────────────────────────────────────────
    USER_USERNAME("user.username", "User login name", INTERNAL),
    USER_EMAIL("user.email", "User email address", INTERNAL),
    USER_PASSWORD_HASH("user.password", "Argon2-hashed password", RESTRICTED),
    USER_ROLE("user.role", "User role (ADMIN, USER, AUDITOR)", INTERNAL),
    USER_ACTIVE_FLAG("user.active", "Whether the account is active", INTERNAL),
    USER_RESET_TOKEN("user.resetToken", "Password reset token (plaintext sent via email)", CONFIDENTIAL),
    USER_RESET_TOKEN_EXPIRY("user.resetTokenExpiresAt", "Password reset token expiration", INTERNAL),
    USER_PASSWORD_HISTORY("user.passwordHistory", "Password history (comma-separated Argon2 hashes)", RESTRICTED),
    USER_TWO_FA_ENABLED("user.twoFaEnabled", "Whether 2FA is enabled", INTERNAL),
    USER_TWO_FA_CODE("user.twoFaCode", "2FA verification code (plaintext)", CONFIDENTIAL),
    USER_TWO_FA_CODE_EXPIRY("user.twoFaCodeExpiresAt", "2FA code expiration", INTERNAL),
    USER_ACCOUNT_LOCKED("user.accountLockedUntilAdmin", "Whether account is locked until admin action", INTERNAL),
    USER_SESSION_VALID_AFTER("user.sessionTokenValidAfter", "Session invalidation timestamp", INTERNAL),

    // ── Credential domain ────────────────────────────────────────────────
    CREDENTIAL_SERVICE_NAME("credential.serviceName", "Name of the service the credential is for", PUBLIC),
    CREDENTIAL_USERNAME("credential.username", "Username for the external service", INTERNAL),
    CREDENTIAL_ENCRYPTED_PASSWORD("credential.encryptedPassword", "AES-256-GCM encrypted password", CONFIDENTIAL),
    CREDENTIAL_URL("credential.url", "URL of the external service", INTERNAL),
    CREDENTIAL_NOTES("credential.notes", "Free-text notes (may contain sensitive information)", CONFIDENTIAL),
    CREDENTIAL_VAULT_ID("credential.vaultId", "Foreign key to the parent vault", INTERNAL),

    // ── Vault domain ────────────────────────────────────────────────────
    VAULT_NAME("vault.name", "Vault display name", PUBLIC),
    VAULT_DESCRIPTION("vault.description", "Vault description", PUBLIC),
    VAULT_OWNER_ID("vault.ownerId", "Foreign key to the vault owner", INTERNAL),

    // ── Audit domain ─────────────────────────────────────────────────────
    AUDIT_ACTION("audit.action", "Audit action type", INTERNAL),
    AUDIT_PERFORMED_BY("audit.performedBy", "User who performed the action", INTERNAL),
    AUDIT_TARGET_RESOURCE("audit.targetResource", "Resource that was acted upon", INTERNAL),
    AUDIT_DETAILS("audit.details", "Detailed audit information (may contain sensitive references)", CONFIDENTIAL),
    AUDIT_TIMESTAMP("audit.timestamp", "When the action occurred", PUBLIC),
    AUDIT_HASH("audit.hash", "SHA-256 hash for integrity verification", INTERNAL),
    AUDIT_PREVIOUS_HASH("audit.previousHash", "Previous audit log SHA-256 hash", INTERNAL),

    // ── JWT / Auth tokens ────────────────────────────────────────────────
    JWT_TOKEN("jwt.token", "JSON Web Token (Bearer token) — plaintext payload is Base64-encoded, not encrypted", CONFIDENTIAL),
    JWT_TOKEN_HASH("jwt.tokenHash", "SHA-256 hash of the JWT token for revocation tracking", INTERNAL),
    JWT_REFRESH_TOKEN("jwt.refreshToken", "JWT refresh token", CONFIDENTIAL),
    HMAC_SIGNATURE("hmac.signature", "HMAC-SHA256 request signature (Base64-encoded)", CONFIDENTIAL),

    // ── Encryption / Security credentials ────────────────────────────────
    ENCRYPTION_SECRET("encryption.secret", "AES-256 encryption master secret", RESTRICTED),
    ENCRYPTION_SALT("encryption.salt", "PBKDF2 salt for key derivation", RESTRICTED),
    ENCRYPTION_PREVIOUS_SECRET("encryption.previousSecret", "Previous encryption secret (key rotation fallback)", RESTRICTED),
    ENCRYPTED_DATA_BASE64("encryption.base64Ciphertext", "Base64-encoded IV + ciphertext (AES-256-GCM output)", CONFIDENTIAL),
    HMAC_SHARED_SECRET("hmac.secret", "HMAC-SHA256 shared secret for request signing", RESTRICTED),
    JWT_SIGNING_SECRET("jwt.secret", "JWT HS256 signing secret", RESTRICTED),

    // ─── File handling / import-export ───────────────────────────────────
    FILE_IMPORT_DATA("file.importData", "Imported credential data (transient, securely deleted after processing)", CONFIDENTIAL),
    FILE_EXPORT_DATA("file.exportData", "Exported credential data (transient, securely deleted)", CONFIDENTIAL),
    FILE_TEMP_PATH("file.tempPath", "Temporary file path for import/export", INTERNAL),

    // ── Environment / Configuration ──────────────────────────────────────
    DATABASE_URL("config.databaseUrl", "Database JDBC URL (may contain credentials)", RESTRICTED),
    DATABASE_USERNAME("config.databaseUsername", "Database login user", RESTRICTED),
    DATABASE_PASSWORD("config.databasePassword", "Database login password", RESTRICTED),
    SMTP_PASSWORD("config.smtpPassword", "SMTP server password for email sending", RESTRICTED),
    SPRING_MAIL_USERNAME("config.mailUsername", "Email server username", RESTRICTED),
    CORS_ALLOWED_ORIGINS("config.corsOrigins", "Allowed CORS origins", INTERNAL);

    private final String fieldPath;
    private final String description;
    private final DataClassification classification;

    SensitiveDataElement(String fieldPath, String description, DataClassification classification) {
        this.fieldPath = fieldPath;
        this.description = description;
        this.classification = classification;
    }

}
