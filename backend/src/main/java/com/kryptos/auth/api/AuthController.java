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
import com.kryptos.auth.application.dto.LoginRequest;
import com.kryptos.auth.application.dto.LoginResponse;
import com.kryptos.auth.application.dto.RegisterRequest;
import com.kryptos.auth.application.dto.TwoFaVerifyRequest;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/2fa/verify")
    public ResponseEntity<AuthResponse> verifyTwoFa(@Valid @RequestBody TwoFaVerifyRequest request) {
        return ResponseEntity.ok(authService.verifyTwoFaCode(request));
    }

    @PostMapping("/2fa/enable")
    public ResponseEntity<Void> enableTwoFa(Principal principal) {
        authService.enableTwoFa(principal.getName());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/2fa/disable")
    public ResponseEntity<Void> disableTwoFa(Principal principal) {
        authService.disableTwoFa(principal.getName());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authHeader,
                                       Principal principal) {
        String token = authHeader.replace("Bearer ", "");
        authService.logout(token, principal.getName());
        return ResponseEntity.ok().build();
    }
}
