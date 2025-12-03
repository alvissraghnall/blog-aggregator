package com.ominimie.auth.service;

import com.ominimie.auth.refresh_token.domain.RefreshToken;
import com.ominimie.auth.refresh_token.repos.RefreshTokenRepository;
import com.ominimie.auth.user.domain.User;
import com.ominimie.auth.user.repos.UserRepository;
import io.grpc.Status;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    
    private static final int REFRESH_TOKEN_LENGTH = 32;
    private static final SecureRandom secureRandom = new SecureRandom();

    @Getter
    @RequiredArgsConstructor
    public static class TokenResponse {
        private final String accessToken;
        private final String refreshToken;
        private final Instant accessTokenExpiresAt;
    }

    public TokenResponse generateTokens(User user, String createdBy) {
        Instant now = Instant.now();
        Instant accessTokenExpiresAt = now.plus(5, ChronoUnit.HOURS);
        Instant refreshTokenExpiresAt = now.plus(7, ChronoUnit.DAYS);

        JwtClaimsSet accessClaims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(accessTokenExpiresAt)
                .subject(user.getId().toString())
                .claim("user_id", user.getId().toString())
                .claim("email", user.getEmail())
                .claim("full_name", user.getFullName())
                .build();

        String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(accessClaims)).getTokenValue();
        
        String refreshToken = generateOpaqueToken();
        
        RefreshToken refreshTokenEntity = new RefreshToken(refreshToken, user, refreshTokenExpiresAt, createdBy);
        refreshTokenRepository.save(refreshTokenEntity);

        return new TokenResponse(accessToken, refreshToken, accessTokenExpiresAt);
    }
    
    public TokenResponse generateTokens(User user) {
        return generateTokens(user, "system");
    }

    public TokenResponse refreshToken(String refreshToken, String createdBy) {
        try {
            RefreshToken tokenEntity = refreshTokenRepository.findByIdAndRevokedFalse(refreshToken)
                    .orElseThrow(() -> new JwtException("Refresh token not found or revoked"));
            
            if (tokenEntity.isExpired()) {
                throw new JwtException("Refresh token expired");
            }
            
            tokenEntity.setRevoked(true);
            refreshTokenRepository.save(tokenEntity);
            
            User user = tokenEntity.getUser();
            return generateTokens(user, createdBy);

        } catch (JwtException e) {
            throw Status.UNAUTHENTICATED
                    .withDescription("Invalid refresh token: " + e.getMessage())
                    .asRuntimeException();
        }
    }
    
    public TokenResponse refreshToken(String refreshToken) {
        return refreshToken(refreshToken, "system");
    }

    public User validateAccessToken(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            
            if (jwt.getExpiresAt().isBefore(Instant.now())) {
                throw new JwtException("Token expired");
            }

            String userIdStr = jwt.getClaimAsString("user_id");
            if (userIdStr == null) {
                throw new JwtException("Invalid token claims");
            }

            UUID userId = UUID.fromString(userIdStr);
            return userRepository.findById(userId)
                    .orElseThrow(() -> new JwtException("User not found"));

        } catch (JwtException e) {
            throw Status.UNAUTHENTICATED
                    .withDescription("Invalid token: " + e.getMessage())
                    .asRuntimeException();
        }
    }
    
    public void revokeRefreshToken(String refreshToken) {
        RefreshToken tokenEntity = refreshTokenRepository.findById(refreshToken)
                .orElseThrow(() -> Status.NOT_FOUND
                        .withDescription("Refresh token not found")
                        .asRuntimeException());
        
        tokenEntity.setRevoked(true);
        refreshTokenRepository.save(tokenEntity);
    }
    
    public void revokeAllUserRefreshTokens(UUID userId) {
        List<RefreshToken> tokens = refreshTokenRepository.findByUserIdAndRevokedFalse(userId);
        tokens.forEach(token -> token.setRevoked(true));
        refreshTokenRepository.saveAll(tokens);
    }
    
    private String generateOpaqueToken() {
        byte[] tokenBytes = new byte[REFRESH_TOKEN_LENGTH];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }
}
