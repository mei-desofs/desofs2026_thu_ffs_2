package com.kryptos.auth.api;

import java.security.Principal;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kryptos.auth.application.AuthService;
import com.kryptos.auth.application.dto.AuthResponse;
import com.kryptos.auth.application.dto.BackupCodeVerifyRequest;
import com.kryptos.auth.application.dto.BackupCodesResponse;
import com.kryptos.auth.application.dto.LoginRequest;
import com.kryptos.auth.application.dto.LoginResponse;
import com.kryptos.auth.application.dto.RegisterRequest;
import com.kryptos.auth.application.dto.TotpSetupResponse;
import com.kryptos.auth.application.dto.TotpVerifyRequest;
import com.kryptos.auth.application.dto.TwoFaVerifyRequest;
import com.kryptos.shared.util.RequestUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
        String ip = RequestUtils.extractClientIp(httpRequest);
        String ua = RequestUtils.extractUserAgent(httpRequest);
        return ResponseEntity.ok(authService.register(request, ip, ua));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            @RequestHeader(value = "X-Device-Fingerprint", required = false) String deviceFingerprint,
            HttpServletRequest httpRequest) {
        String ip = RequestUtils.extractClientIp(httpRequest);
        String ua = RequestUtils.extractUserAgent(httpRequest);
        return ResponseEntity.ok(authService.login(request, deviceFingerprint, ip, ua));
    }

    @PostMapping("/2fa/verify")
    public ResponseEntity<AuthResponse> verifyTwoFa(@Valid @RequestBody TwoFaVerifyRequest request, HttpServletRequest httpRequest) {
        String ip = RequestUtils.extractClientIp(httpRequest);
        String ua = RequestUtils.extractUserAgent(httpRequest);
        return ResponseEntity.ok(authService.verifyTwoFaCode(request, ip, ua));
    }

    @PostMapping("/2fa/verify-backup-code")
    public ResponseEntity<AuthResponse> verifyBackupCode(@Valid @RequestBody BackupCodeVerifyRequest request, HttpServletRequest httpRequest) {
        String ip = RequestUtils.extractClientIp(httpRequest);
        String ua = RequestUtils.extractUserAgent(httpRequest);
        return ResponseEntity.ok(authService.verifyBackupCode(request, ip, ua));
    }

    @PostMapping("/2fa/enable")
    public ResponseEntity<BackupCodesResponse> enableTwoFa(Principal principal) {
        return ResponseEntity.ok(authService.enableTwoFa(principal.getName()));
    }

    @PostMapping("/2fa/disable")
    public ResponseEntity<Void> disableTwoFa(Principal principal) {
        authService.disableTwoFa(principal.getName());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/totp/setup")
    public ResponseEntity<TotpSetupResponse> setupTotp(Principal principal) {
        return ResponseEntity.ok(authService.setupTotp(principal.getName()));
    }

    @PostMapping("/totp/confirm")
    public ResponseEntity<Void> confirmTotpSetup(Principal principal,
            @RequestHeader("X-TOTP-Secret") String secret,
            @RequestHeader("X-TOTP-Code") String code) {
        authService.confirmTotpSetup(principal.getName(), secret, code);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/totp/disable")
    public ResponseEntity<Void> disableTotp(Principal principal) {
        authService.disableTotp(principal.getName());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/totp/verify")
    public ResponseEntity<AuthResponse> verifyTotp(@Valid @RequestBody TotpVerifyRequest request, HttpServletRequest httpRequest) {
        String ip = RequestUtils.extractClientIp(httpRequest);
        String ua = RequestUtils.extractUserAgent(httpRequest);
        return ResponseEntity.ok(authService.verifyTotp(request, ip, ua));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authHeader,
                                       Principal principal) {
        String token = authHeader.replace("Bearer ", "");
        authService.logout(token, principal.getName());
        return ResponseEntity.ok().build();
    }
}
