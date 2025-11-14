
package com.ominimie.auth.service.oauth2;

import java.time.Instant;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class OAuth2TokenResponse {
    private OAuth2AccessToken accessToken;
    private OAuth2RefreshToken refreshToken;

    public String getAccessTokenValue() {
        return accessToken.getTokenValue();
    }

    public String getRefreshTokenValue() {
        return refreshToken.getTokenValue();
    }

    public Instant getAccessTokenExpiresAt() {
        return accessToken.getExpiresAt();
    }
}
