package com.kryptos.audit.domain;

public final class AuditAction {

    private AuditAction() {}

    public static final String LOGIN = "LOGIN";
    public static final String LOGIN_FAILED = "LOGIN_FAILED";
    public static final String REGISTER = "REGISTER";
    public static final String CREDENTIAL_CREATE = "CREDENTIAL_CREATE";
    public static final String CREDENTIAL_UPDATE = "CREDENTIAL_UPDATE";
    public static final String CREDENTIAL_DELETE = "CREDENTIAL_DELETE";
    public static final String VAULT_CREATE = "VAULT_CREATE";
    public static final String VAULT_UPDATE = "VAULT_UPDATE";
    public static final String VAULT_DELETE = "VAULT_DELETE";
    public static final String USER_DELETE = "USER_DELETE";
    public static final String USER_ROLE_UPDATE = "USER_ROLE_UPDATE";
    public static final String DEVICE_REGISTER = "DEVICE_REGISTER";
    public static final String DEVICE_UPDATE = "DEVICE_UPDATE";
    public static final String DEVICE_REVOKE = "DEVICE_REVOKE";
    public static final String EXPORT = "EXPORT";
    public static final String IMPORT = "IMPORT";
    public static final String SECURE_WIPE = "SECURE_WIPE";
    public static final String SECURE_WIPE_FAILED = "SECURE_WIPE_FAILED";
}
