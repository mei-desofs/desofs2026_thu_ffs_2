package com.kryptos.credential.api;

import com.kryptos.credential.application.CredentialService;
import com.kryptos.credential.application.dto.CreateCredentialRequest;
import com.kryptos.credential.application.dto.CredentialResponse;
import com.kryptos.shared.security.KryptosUserDetails;
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
@RequestMapping("/api/credentials")
@RequiredArgsConstructor
public class CredentialController {

    private final CredentialService credentialService;

    @PostMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<CredentialResponse> create(
            @Valid @RequestBody CreateCredentialRequest request,
            @AuthenticationPrincipal KryptosUserDetails principal) {
        UUID ownerId = principal.getId();
        return ResponseEntity.status(HttpStatus.CREATED).body(credentialService.create(request, ownerId));
    }

    @GetMapping("/vault/{vaultId}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<CredentialResponse>> findByVault(
            @PathVariable UUID vaultId,
            @AuthenticationPrincipal KryptosUserDetails principal) {
        UUID ownerId = principal.getId();
        return ResponseEntity.ok(credentialService.findAllByVault(vaultId, ownerId));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<CredentialResponse> findById(
            @PathVariable UUID id,
            @AuthenticationPrincipal KryptosUserDetails principal) {
        UUID ownerId = principal.getId();
        return ResponseEntity.ok(credentialService.findById(id, ownerId));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Void> delete(
            @PathVariable UUID id,
            @AuthenticationPrincipal KryptosUserDetails principal) {
        UUID ownerId = principal.getId();
        credentialService.delete(id, ownerId);
        return ResponseEntity.noContent().build();
    }
}
