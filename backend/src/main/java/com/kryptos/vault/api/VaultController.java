package com.kryptos.vault.api;

import com.kryptos.vault.application.VaultService;
import com.kryptos.vault.application.dto.CreateVaultRequest;
import com.kryptos.vault.application.dto.VaultResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/vaults")
@RequiredArgsConstructor
public class VaultController {

    private final VaultService vaultService;

    @PostMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<VaultResponse> create(@Valid @RequestBody CreateVaultRequest request) {
        // TODO: extract ownerId from SecurityContext
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<VaultResponse>> findAll() {
        // TODO: extract ownerId from SecurityContext
        return ResponseEntity.ok(List.of());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<VaultResponse> findById(@PathVariable UUID id) {
        // TODO
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<Void> delete(@PathVariable UUID id) {
        // TODO
        return ResponseEntity.noContent().build();
    }
}
