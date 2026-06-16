package com.kryptos.user.api;

import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.kryptos.user.application.AdminUserService;
import com.kryptos.user.application.dto.AdminPasswordResetResponse;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/admin/users")
@PreAuthorize("hasRole('ADMIN')")
@RequiredArgsConstructor
public class AdminUserController {

    private final AdminUserService adminUserService;

    @PostMapping("/{userId}/reset-password")
    public ResponseEntity<AdminPasswordResetResponse> resetUserPassword(@PathVariable UUID userId) {
        AdminPasswordResetResponse response = adminUserService.initiatePasswordReset(userId);
        return ResponseEntity.ok(response);
    }
}
