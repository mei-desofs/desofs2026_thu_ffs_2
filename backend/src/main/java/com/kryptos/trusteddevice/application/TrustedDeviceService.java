package com.kryptos.trusteddevice.application;

import com.kryptos.trusteddevice.application.dto.RegisterDeviceRequest;
import com.kryptos.trusteddevice.application.dto.TrustedDeviceResponse;
import com.kryptos.trusteddevice.domain.TrustedDeviceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TrustedDeviceService {

    private final TrustedDeviceRepository trustedDeviceRepository;

    public TrustedDeviceResponse register(RegisterDeviceRequest request, UUID userId) {
        // TODO
        return null;
    }

    public List<TrustedDeviceResponse> findAllByUser(UUID userId) {
        // TODO
        return List.of();
    }

    public void revoke(UUID deviceId, UUID userId) {
        // TODO: verify ownership before revoking
    }
}
