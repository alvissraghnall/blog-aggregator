package com.ominimie.auth.service;

import com.ominimie.auth.user.domain.User;
import com.ominimie.auth.user.repos.UserRepository;
import io.grpc.Status;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final UserRepository userRepository;

    @Getter
    @RequiredArgsConstructor
    public static class TokenResponse {
        private final String accessToken;
        private final String refreshToken;
        private final Instant accessTokenExpiresAt;
    }

    public TokenResponse generateTokens(User user) {
        Instant now = Instant.now();
        Instant accessTokenExpiresAt = now.plus(5, ChronoUnit.HOURS); // 5 hours access token
        Instant refreshTokenExpiresAt = now.plus(2, ChronoUnit.WEEKS); // 14 day refresh token

        JwtClaimsSet accessClaims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(accessTokenExpiresAt)
                .subject(user.getId().toString()) 
                .claim("user_id", user.getId().toString())
                .claim("email", user.getEmail())
                .claim("full_name", user.getFullName())
                .build();

        JwtClaimsSet refreshClaims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(refreshTokenExpiresAt)
                .subject(user.getId().toString())
                .build();

        String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(accessClaims)).getTokenValue();
        String refreshToken = jwtEncoder.encode(JwtEncoderParameters.from(refreshClaims)).getTokenValue();

        return new TokenResponse(accessToken, refreshToken, accessTokenExpiresAt);
    }

    public TokenResponse refreshToken(String refreshToken) {
        try {
            Jwt jwt = jwtDecoder.decode(refreshToken);
            
            if (jwt.getExpiresAt().isBefore(Instant.now())) {
                throw new JwtException("Refresh token expired");
            }
            
            UUID userId = UUID.fromString(jwt.getSubject());
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new JwtException("User not found"));

            return generateTokens(user);

        } catch (JwtException e) {
            throw Status.UNAUTHENTICATED
                    .withDescription("Invalid refresh token: " + e.getMessage())
                    .asRuntimeException();
        }
    }

    public User validateToken(String token) {
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
}
