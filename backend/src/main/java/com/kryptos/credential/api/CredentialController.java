package com.kryptos.credential.api;

import com.kryptos.credential.application.CredentialService;
import com.kryptos.credential.application.dto.CreateCredentialRequest;
import com.kryptos.credential.application.dto.CredentialResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
    public ResponseEntity<CredentialResponse> create(@Valid @RequestBody CreateCredentialRequest request) {
        // TODO: extract ownerId from SecurityContext
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping("/vault/{vaultId}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<CredentialResponse>> findByVault(@PathVariable UUID vaultId) {
        // TODO: extract ownerId from SecurityContext
        return ResponseEntity.ok(List.of());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<CredentialResponse> findById(@PathVariable UUID id) {
        // TODO
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Void> delete(@PathVariable UUID id) {
        // TODO
        return ResponseEntity.noContent().build();
    }
}
