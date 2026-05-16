package com.kryptos.trusteddevice.api;

import com.kryptos.shared.security.KryptosUserDetails;
import com.kryptos.trusteddevice.application.TrustedDeviceService;
import com.kryptos.trusteddevice.application.dto.RegisterDeviceRequest;
import com.kryptos.trusteddevice.application.dto.TrustedDeviceResponse;
import com.kryptos.trusteddevice.application.dto.UpdateDeviceRequest;
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
@RequestMapping("/api/devices")
@RequiredArgsConstructor
public class TrustedDeviceController {

    private final TrustedDeviceService trustedDeviceService;

    @PostMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<TrustedDeviceResponse> register(
            @Valid @RequestBody RegisterDeviceRequest request,
            @AuthenticationPrincipal KryptosUserDetails principal) {
        UUID ownerId = principal.getId();
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(trustedDeviceService.register(request, ownerId));
    }

    @GetMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<TrustedDeviceResponse>> findAll(
            @AuthenticationPrincipal KryptosUserDetails principal) {
        return ResponseEntity.ok(trustedDeviceService.findAllByOwner(principal.getId()));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<TrustedDeviceResponse> findById(
            @PathVariable UUID id,
            @AuthenticationPrincipal KryptosUserDetails principal) {
        return ResponseEntity.ok(trustedDeviceService.findById(id, principal.getId()));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<TrustedDeviceResponse> update(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateDeviceRequest request,
            @AuthenticationPrincipal KryptosUserDetails principal) {
        return ResponseEntity.ok(trustedDeviceService.updateName(id, request, principal.getId()));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Void> revoke(
            @PathVariable UUID id,
            @AuthenticationPrincipal KryptosUserDetails principal) {
        trustedDeviceService.revoke(id, principal.getId());
        return ResponseEntity.noContent().build();
    }
}
