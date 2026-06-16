package com.kryptos.credential.api;

import com.kryptos.credential.application.CryptoMigrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/admin/crypto")
@RequiredArgsConstructor
public class CryptoMigrationController {

    private final CryptoMigrationService cryptoMigrationService;

    @PostMapping("/migrate")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> migrateCrypto() {
        int migratedCount = cryptoMigrationService.migrateAllCredentials();
        return ResponseEntity.ok(Map.of(
                "message", "Crypto migration completed successfully.",
                "migratedRecords", migratedCount
        ));
    }
}
