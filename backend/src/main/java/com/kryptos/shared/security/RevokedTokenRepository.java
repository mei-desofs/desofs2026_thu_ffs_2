package com.kryptos.shared.security;

import org.springframework.data.jpa.repository.JpaRepository;
import java.time.LocalDateTime;
import java.util.UUID;

public interface RevokedTokenRepository extends JpaRepository<RevokedToken, UUID> {

    boolean existsByTokenHashAndExpiresAtAfter(String tokenHash, LocalDateTime now);
}
