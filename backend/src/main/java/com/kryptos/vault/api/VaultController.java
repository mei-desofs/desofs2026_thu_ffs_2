package com.kryptos.vault.api;

import com.kryptos.shared.security.KryptosUserDetails;
import com.kryptos.vault.application.VaultService;
import com.kryptos.vault.application.dto.CreateVaultRequest;
import com.kryptos.vault.application.dto.VaultResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
    public ResponseEntity<VaultResponse> create(
            @Valid @RequestBody CreateVaultRequest request,
            @AuthenticationPrincipal KryptosUserDetails principal) {
        UUID ownerId = principal.getId();
        return ResponseEntity.status(HttpStatus.CREATED).body(vaultService.create(request, ownerId));
    }

    @GetMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<VaultResponse>> findAll(
            @AuthenticationPrincipal KryptosUserDetails principal) {
        UUID ownerId = principal.getId();
        return ResponseEntity.ok(vaultService.findAllByOwner(ownerId));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<VaultResponse> findById(
            @PathVariable UUID id,
            @AuthenticationPrincipal KryptosUserDetails principal) {
        UUID ownerId = principal.getId();
        return ResponseEntity.ok(vaultService.findById(id, ownerId));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Void> delete(
            @PathVariable UUID id,
            @AuthenticationPrincipal KryptosUserDetails principal) {
        UUID ownerId = principal.getId();
        vaultService.delete(id, ownerId);
        return ResponseEntity.noContent().build();
    }
}
