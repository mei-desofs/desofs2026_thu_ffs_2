package com.kryptos.trusteddevice.api;

import com.kryptos.trusteddevice.application.TrustedDeviceService;
import com.kryptos.trusteddevice.application.dto.RegisterDeviceRequest;
import com.kryptos.trusteddevice.application.dto.TrustedDeviceResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
    public ResponseEntity<TrustedDeviceResponse> register(@Valid @RequestBody RegisterDeviceRequest request) {
        // TODO: extract userId from SecurityContext
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<TrustedDeviceResponse>> findAll() {
        // TODO: extract userId from SecurityContext
        return ResponseEntity.ok(List.of());
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Void> revoke(@PathVariable UUID id) {
        // TODO: extract userId from SecurityContext
        return ResponseEntity.noContent().build();
    }
}
