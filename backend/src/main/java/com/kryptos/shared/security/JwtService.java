package com.kryptos.shared.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HexFormat;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final RevokedTokenRepository revokedTokenRepository;

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    private static final String AUDIENCE = "kryptos";

    public String generateToken(String username, String role) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .audience().add(AUDIENCE).and()
                .issuedAt(now)
                .expiration(expiry)
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractIssuedAt(String token) {
        return extractClaim(token, Claims::getIssuedAt);
    }

    public void requireRecentAuthentication() {
        var auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getCredentials() instanceof String token)) {
            throw new com.kryptos.shared.exception.ReauthenticationRequiredException("Re-authentication missing.");
        }
        Date issuedAt = extractIssuedAt(token);
        if (issuedAt == null || issuedAt.toInstant().isBefore(Instant.now().minusSeconds(300))) {
            throw new com.kryptos.shared.exception.ReauthenticationRequiredException("Re-authentication required for sensitive operations.");
        }
    }

    public boolean isTokenValid(String token, KryptosUserDetails userDetails) {
        try {
            String tokenUsername = extractUsername(token);
            if (userDetails == null || !userDetails.getUsername().equals(tokenUsername)) {
                return false;
            }
            if (isTokenExpired(token) || isTokenRevoked(token)) {
                return false;
            }
            
            Date issuedAt = extractClaim(token, Claims::getIssuedAt);
            if (userDetails.getSessionTokenValidAfter() != null && issuedAt != null) {
                Date validAfter = Date.from(userDetails.getSessionTokenValidAfter().atZone(ZoneId.systemDefault()).toInstant());
                if (issuedAt.before(validAfter)) {
                    return false;
                }
            }
            
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            return false;
        }
    }

    public void revokeToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            LocalDateTime expiresAt = Instant.ofEpochMilli(
                    claims.getExpiration().getTime())
                    .atZone(ZoneId.systemDefault()).toLocalDateTime();

            String tokenHash = hashToken(token);
            revokedTokenRepository.save(new RevokedToken(tokenHash, expiresAt));
        } catch (Exception e) {
            throw new RuntimeException("Failed to revoke token", e);
        }
    }

    public boolean isTokenRevoked(String token) {
        String tokenHash = hashToken(token);
        return revokedTokenRepository.existsByTokenHashAndExpiresAtAfter(
                tokenHash, LocalDateTime.now());
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private SecretKey getSigningKey() {
        // HS256 requires at least 256-bit key (32 bytes).
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException("jwt.secret must be at least 32 bytes");
        }
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .requireAudience(AUDIENCE)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private <T> T extractClaim(String token, Function<Claims, T> resolver) {
        return resolver.apply(extractAllClaims(token));
    }

    private boolean isTokenExpired(String token) {
        Date exp = extractClaim(token, Claims::getExpiration);
        return exp.before(new Date());
    }
}
