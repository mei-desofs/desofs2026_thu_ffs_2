package com.kryptos.auth.application;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.kryptos.audit.application.AuditService;
import com.kryptos.audit.domain.AuditAction;
import com.kryptos.auth.application.dto.AuthResponse;
import com.kryptos.shared.validation.PasswordValidator;
import com.kryptos.auth.application.dto.LoginRequest;
import com.kryptos.auth.application.dto.LoginResponse;
import com.kryptos.auth.application.dto.PasswordResetConfirm;
import com.kryptos.auth.application.dto.PasswordResetRequest;
import com.kryptos.auth.application.dto.RegisterRequest;
import com.kryptos.auth.application.dto.TwoFaVerifyRequest;
import com.kryptos.shared.email.EmailService;
import com.kryptos.shared.exception.InvalidTokenException;
import com.kryptos.shared.exception.RateLimitExceededException;
import com.kryptos.shared.exception.ResourceNotFoundException;
import com.kryptos.shared.security.JwtService;
import com.kryptos.trusteddevice.domain.TrustedDeviceRepository;
import com.kryptos.user.domain.Role;
import com.kryptos.user.domain.User;
import com.kryptos.user.domain.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final AuditService auditService;
    private final EmailService emailService;
    private final TrustedDeviceRepository trustedDeviceRepository;
    private final SuspiciousAuthNotificationService suspiciousAuthNotificationService;

    private final ConcurrentHashMap<String, Integer> loginAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Instant> lockouts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Integer> resetAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Instant> resetLockouts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Integer> twoFaAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Integer> resetFailures = new ConcurrentHashMap<>();
    private static final int MAX_ATTEMPTS = 5;
    private static final int MAX_RESET_ATTEMPTS = 3;
    private static final int MAX_RESET_FAILURES = 3;
    private static final int MAX_2FA_ATTEMPTS = 5;
    private static final int RESET_LOCKOUT_SECONDS = 300;
    private static final int TWO_FA_CODE_EXPIRY_MINUTES = 5;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public AuthResponse register(RegisterRequest request, String ipAddress, String userAgent) {
        PasswordValidator.validatePassword(request.password());

        boolean emailExists = userRepository.findByEmail(request.email()).isPresent();
        boolean usernameExists = userRepository.findByUsername(request.username()).isPresent();

        if (emailExists || usernameExists) {
            String reason = emailExists ? "Email already in use" : "Username already in use";
            auditService.log(AuditAction.REGISTER, request.username(), "auth",
                    "Registration failed - " + reason + " - potential enumeration attempt");
            throw new IllegalArgumentException("Registration failed");
        }

        User user = User.builder()
                .username(request.username())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.USER)
                .active(true)
                .build();

        user.setSessionTokenValidAfter(LocalDateTime.now().minusSeconds(1));
        userRepository.save(user);

        String jwtToken = jwtService.generateToken(user.getUsername(), user.getRole().name(), ipAddress, userAgent);

        auditService.log(AuditAction.REGISTER, request.username(), "auth", "User registered");

        return new AuthResponse(jwtToken, user.getUsername(), user.getRole().name());
    }

    public LoginResponse login(LoginRequest request, String deviceFingerprint, String ipAddress, String userAgent) {
        String providedId = request.username();

        String cacheKey = userRepository.findByUsername(providedId)
                .or(() -> userRepository.findByEmail(providedId))
                .map(User::getUsername)
                .orElse(providedId);

        User userOpt = userRepository.findByUsername(cacheKey).orElse(null);
        if (userOpt != null && userOpt.isAccountLockedUntilAdmin()) {
            auditService.log(AuditAction.LOGIN_FAILED, cacheKey, "auth",
                    "Login blocked - account locked by admin");
            throw new RateLimitExceededException("Account locked. Contact administrator.");
        }

        if (lockouts.containsKey(cacheKey) && lockouts.get(cacheKey).isAfter(Instant.now())) {
            auditService.log(AuditAction.LOGIN_FAILED, cacheKey, "auth",
                    "Login blocked - account locked due to " + MAX_ATTEMPTS + " failed attempts");
            throw new RateLimitExceededException("Too many failed attempts. Try again later.");
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(providedId, request.password())
            );

            loginAttempts.remove(cacheKey);
            lockouts.remove(cacheKey);

            var user = userRepository.findByUsername(cacheKey).orElseThrow();

            if (user.isTwoFaEnabled()) {
                boolean isTrustedDevice = false;
                if (deviceFingerprint != null && !deviceFingerprint.isBlank()) {
                    isTrustedDevice = trustedDeviceRepository.findByDeviceFingerprint(deviceFingerprint)
                            .map(device -> device.getUser().getId().equals(user.getId()) && device.isActive())
                            .orElse(false);
                }

                if (isTrustedDevice) {
                    auditService.log(AuditAction.LOGIN, cacheKey, "auth",
                        "Adaptive Auth: 2FA bypassed for known Trusted Device (" + deviceFingerprint + ")");
                } else {
                    sendTwoFaCode(user);
                    auditService.log(AuditAction.LOGIN, cacheKey, "auth", "Password valid, 2FA code sent for untrusted device");
                    return LoginResponse.twoFaRequired(user.getUsername());
                }
            }

            user.setSessionTokenValidAfter(LocalDateTime.now().minusSeconds(1));
            userRepository.save(user);
            String jwtToken = jwtService.generateToken(user.getUsername(), user.getRole().name(), ipAddress, userAgent);
            auditService.log(AuditAction.LOGIN, cacheKey, "auth", "User logged in");
            return LoginResponse.authenticated(jwtToken, user.getUsername(), user.getRole().name());

        } catch (Exception e) {
            int attempts = loginAttempts.getOrDefault(cacheKey, 0) + 1;
            loginAttempts.put(cacheKey, attempts);

            auditService.log(AuditAction.LOGIN_FAILED, cacheKey, "auth",
                    "Failed login attempt " + attempts + "/" + MAX_ATTEMPTS);

            if (attempts >= 3 && attempts < MAX_ATTEMPTS) {
                User user = userRepository.findByUsername(cacheKey).orElse(null);
                if (user != null) {
                    suspiciousAuthNotificationService.notifySuspiciousAttempt(
                        new com.kryptos.auth.application.dto.SuspiciousAuthAttempt(
                            user.getUsername(),
                            user.getEmail(),
                            "Multiple failed login attempts (" + attempts + "/" + MAX_ATTEMPTS + ")",
                            ipAddress,
                            userAgent,
                            LocalDateTime.now()
                        )
                    );
                }
            }

            if (attempts >= MAX_ATTEMPTS) {
                lockouts.put(cacheKey, Instant.now().plusSeconds(900));
                auditService.log(AuditAction.LOGIN_FAILED, cacheKey, "auth",
                        "Account locked after " + MAX_ATTEMPTS + " failed login attempts");
                User user = userRepository.findByUsername(cacheKey).orElse(null);
                if (user != null) {
                    suspiciousAuthNotificationService.notifySuspiciousAttempt(
                        new com.kryptos.auth.application.dto.SuspiciousAuthAttempt(
                            user.getUsername(),
                            user.getEmail(),
                            "Account locked due to " + MAX_ATTEMPTS + " failed login attempts",
                            ipAddress,
                            userAgent,
                            LocalDateTime.now()
                        )
                    );
                }
            }
            throw new IllegalArgumentException("Invalid credentials");
        }
    }

    @Transactional
    public AuthResponse verifyTwoFaCode(TwoFaVerifyRequest request, String ipAddress, String userAgent) {
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new IllegalArgumentException("Invalid credentials"));

        int attempts = twoFaAttempts.getOrDefault(user.getUsername(), 0);
        if (attempts >= MAX_2FA_ATTEMPTS) {
            auditService.log(AuditAction.LOGIN_FAILED, user.getUsername(), "auth",
                    "2FA verification blocked - too many attempts");
            throw new RateLimitExceededException(
                    "Too many 2FA attempts. Request a new code.");
        }

        if (user.getTwoFaCode() == null || user.getTwoFaCodeExpiresAt() == null) {
            throw new IllegalArgumentException("No 2FA code pending. Please login again.");
        }

        if (user.getTwoFaCodeExpiresAt().isBefore(LocalDateTime.now())) {
            user.setTwoFaCode(null);
            user.setTwoFaCodeExpiresAt(null);
            userRepository.save(user);
            throw new InvalidTokenException("2FA code has expired. Please login again.");
        }

        if (!user.getTwoFaCode().equals(request.code())) {
            twoFaAttempts.put(user.getUsername(), attempts + 1);
            auditService.log(AuditAction.LOGIN_FAILED, user.getUsername(), "auth",
                    "Invalid 2FA code attempt " + (attempts + 1) + "/" + MAX_2FA_ATTEMPTS);
            throw new IllegalArgumentException("Invalid 2FA code");
        }

        // Code is valid — clear it and issue token
        user.setTwoFaCode(null);
        user.setTwoFaCodeExpiresAt(null);
        user.setSessionTokenValidAfter(LocalDateTime.now().minusSeconds(1));
        userRepository.save(user);
        twoFaAttempts.remove(user.getUsername());

        String jwtToken = jwtService.generateToken(user.getUsername(), user.getRole().name(), ipAddress, userAgent);
        auditService.log(AuditAction.LOGIN, user.getUsername(), "auth", "2FA verified, user logged in");

        return new AuthResponse(jwtToken, user.getUsername(), user.getRole().name());
    }


    @Transactional
    public void enableTwoFa(String username) {
        jwtService.requireRecentAuthentication();
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.isTwoFaEnabled()) {
            throw new IllegalArgumentException("2FA is already enabled");
        }

        user.setTwoFaEnabled(true);
        userRepository.save(user);
        auditService.log(AuditAction.REGISTER, username, "auth", "2FA enabled");

        suspiciousAuthNotificationService.notifySuspiciousAttempt(
            new com.kryptos.auth.application.dto.SuspiciousAuthAttempt(
                user.getUsername(),
                user.getEmail(),
                "Two-factor authentication has been enabled on your account",
                "unknown",
                "unknown",
                LocalDateTime.now()
            )
        );
    }

    @Transactional
    public void disableTwoFa(String username) {
        jwtService.requireRecentAuthentication();
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!user.isTwoFaEnabled()) {
            throw new IllegalArgumentException("2FA is not enabled");
        }

        user.setTwoFaEnabled(false);
        user.setTwoFaCode(null);
        user.setTwoFaCodeExpiresAt(null);
        userRepository.save(user);
        auditService.log(AuditAction.REGISTER, username, "auth", "2FA disabled");

        suspiciousAuthNotificationService.notifySuspiciousAttempt(
            new com.kryptos.auth.application.dto.SuspiciousAuthAttempt(
                user.getUsername(),
                user.getEmail(),
                "Two-factor authentication has been disabled on your account",
                "unknown",
                "unknown",
                LocalDateTime.now()
            )
        );
    }

    private void sendTwoFaCode(User user) {
        String code = generateSecureCode();
        user.setTwoFaCode(code);
        user.setTwoFaCodeExpiresAt(LocalDateTime.now().plusMinutes(TWO_FA_CODE_EXPIRY_MINUTES));
        userRepository.save(user);
        emailService.sendTwoFaCode(user.getEmail(), code);
    }

    private String generateSecureCode() {
        int code = SECURE_RANDOM.nextInt(900000) + 100000; // 6 digits: 100000-999999
        return String.valueOf(code);
    }

    private boolean isResetLocked(String email) {
        return resetLockouts.containsKey(email) && resetLockouts.get(email).isAfter(Instant.now());
    }

    private boolean isPasswordInHistory(User user, String newPassword) {
        for (String oldPasswordHash : user.getPasswordHistoryList()) {
            if (passwordEncoder.matches(newPassword, oldPasswordHash)) {
                return true;
            }
        }
        return false;
    }

    @Transactional
    public void requestPasswordReset(PasswordResetRequest request) {
        String email = request.email();

        if (isResetLocked(email)) {
            auditService.log(AuditAction.PASSWORD_RESET_REQUESTED, email, "auth",
                    "Password reset blocked - too many attempts");
            throw new RateLimitExceededException(
                    "Too many password reset requests. Try again later.");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException(
                    "User with email " + email + " not found"));

        int attempts = resetAttempts.getOrDefault(email, 0) + 1;
        resetAttempts.put(email, attempts);

        if (attempts >= MAX_RESET_ATTEMPTS) {
            resetLockouts.put(email, Instant.now().plusSeconds(RESET_LOCKOUT_SECONDS));
            auditService.log(AuditAction.PASSWORD_RESET_REQUESTED, email, "auth",
                    "Password reset rate limit exceeded - account locked");
        }

        String resetToken = UUID.randomUUID().toString();
        user.setResetToken(resetToken);
        user.setResetTokenExpiresAt(LocalDateTime.now().plusMinutes(15));
        userRepository.save(user);

        auditService.log(AuditAction.PASSWORD_RESET_REQUESTED, email, "auth",
                "Password reset requested for user");

        suspiciousAuthNotificationService.notifySuspiciousAttempt(
            new com.kryptos.auth.application.dto.SuspiciousAuthAttempt(
                user.getUsername(),
                user.getEmail(),
                "Password reset request initiated for your account",
                "unknown",
                "unknown",
                LocalDateTime.now()
            )
        );

        // TODO: emailService.sendPasswordResetEmail(user.getEmail(), resetToken);
    }

    @Transactional
    public void confirmPasswordReset(PasswordResetConfirm confirm) {
        User user = userRepository.findByResetToken(confirm.token())
                .orElseThrow(() -> {
                    incrementResetFailure(confirm.token());
                    return new InvalidTokenException("Invalid reset token");
                });

        if (user.getResetTokenExpiresAt() == null ||
            user.getResetTokenExpiresAt().isBefore(LocalDateTime.now())) {
            incrementResetFailure(user.getUsername());
            throw new InvalidTokenException("Reset token has expired");
        }

        PasswordValidator.validatePassword(confirm.newPassword());

        if (isPasswordInHistory(user, confirm.newPassword())) {
            throw new IllegalArgumentException("Cannot reuse one of your last 3 passwords");
        }

        String encodedPassword = passwordEncoder.encode(confirm.newPassword());
        user.addToPasswordHistory(user.getPassword());
        user.setPassword(encodedPassword);
        user.setResetToken(null);
        user.setResetTokenExpiresAt(null);
        user.setSessionTokenValidAfter(LocalDateTime.now()); // V8.3.2 Fix: Invalidate all sessions
        resetFailures.remove(user.getUsername());
        userRepository.save(user);

        auditService.log(AuditAction.PASSWORD_RESET_COMPLETED, user.getUsername(), "auth",
                "Password reset completed successfully");

        suspiciousAuthNotificationService.notifySuspiciousAttempt(
            new com.kryptos.auth.application.dto.SuspiciousAuthAttempt(
                user.getUsername(),
                user.getEmail(),
                "Your password has been changed. If you did not make this change, please contact support immediately.",
                "unknown",
                "unknown",
                LocalDateTime.now()
            )
        );
    }

    public void logout(String token, String username) {
        jwtService.revokeToken(token);
        auditService.log(AuditAction.LOGOUT, username, "auth", "User logged out");
    }

    private void incrementResetFailure(String username) {
        int failures = resetFailures.getOrDefault(username, 0) + 1;
        resetFailures.put(username, failures);

        User user = userRepository.findByUsername(username).orElse(null);
        if (user != null && failures >= MAX_RESET_FAILURES) {
            user.setAccountLockedUntilAdmin(true);
            userRepository.save(user);
            auditService.log(AuditAction.LOGIN_FAILED, username, "auth",
                    "Account locked after " + MAX_RESET_FAILURES + " failed password reset attempts");
        }
    }
}
