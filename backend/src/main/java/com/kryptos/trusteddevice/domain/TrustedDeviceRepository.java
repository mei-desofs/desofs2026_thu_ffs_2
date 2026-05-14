package com.kryptos.trusteddevice.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TrustedDeviceRepository extends JpaRepository<TrustedDevice, UUID> {
    List<TrustedDevice> findAllByUserId(UUID userId);
    Optional<TrustedDevice> findByDeviceFingerprint(String fingerprint);
    boolean existsByIdAndUserId(UUID id, UUID userId);
}
