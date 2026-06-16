package com.kryptos.shared.security;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "revoked_tokens")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RevokedToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(nullable = false)
    private LocalDateTime revokedAt;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    public RevokedToken(String tokenHash, LocalDateTime expiresAt) {
        this.tokenHash = tokenHash;
        this.revokedAt = LocalDateTime.now();
        this.expiresAt = expiresAt;
    }
}
