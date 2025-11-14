package com.ominimie.auth.oauth2_authorization.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ominimie.auth.oauth2_authorization.domain.Oauth2Authorization;
import com.ominimie.auth.oauth2_authorization.repos.Oauth2AuthorizationRepository;
import com.ominimie.auth.service.PrimarySequenceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class MongoOauth2AuthorizationService implements OAuth2AuthorizationService {
    
    private final Oauth2AuthorizationRepository authorizationRepository;
    private final ObjectMapper objectMapper;
    
    @Override
    public void save(OAuth2Authorization authorization) {
        Oauth2Authorization entity = mapToEntity(authorization);
        authorizationRepository.save(entity);
    }
    
    @Override
    public void remove(OAuth2Authorization authorization) {
        authorizationRepository.deleteById(Long.valueOf(authorization.getId()));
    }
    
    @Override
    public OAuth2Authorization findById(String id) {
        return authorizationRepository.findById(Long.valueOf(id))
                .map(this::mapToAuthorization)
                .orElse(null);
    }
    
    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (tokenType == null) {
            return authorizationRepository.findByState(token)
                    .map(this::mapToAuthorization)
                    .orElse(null);
        }
        
        return switch (tokenType.getValue()) {
            case "code" -> authorizationRepository.findByAuthorizationCodeValue(token)
                    .map(this::mapToAuthorization)
                    .orElse(null);
            case "access_token" -> authorizationRepository.findByAccessTokenValue(token)
                    .map(this::mapToAuthorization)
                    .orElse(null);
            case "refresh_token" -> authorizationRepository.findByRefreshTokenValue(token)
                    .map(this::mapToAuthorization)
                    .orElse(null);
            case "id_token" -> authorizationRepository.findByOidcIdTokenValue(token)
                    .map(this::mapToAuthorization)
                    .orElse(null);
            default -> null;
        };
    }
    
    private Oauth2Authorization mapToEntity(OAuth2Authorization authorization) {
        Oauth2Authorization.Oauth2AuthorizationBuilder builder = Oauth2Authorization.builder()
            .id(authorization.getId() != null ? Long.valueOf(authorization.getId()) : null)
            .registeredClientId(authorization.getRegisteredClientId())
            .principalName(authorization.getPrincipalName())
            .authorizationGrantType(authorization.getAuthorizationGrantType().getValue())
            .attributes(writeMap(authorization.getAttributes()))
            .state(authorization.getAttribute("state"));
        
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);
        if (authorizationCode != null) {
            builder.authorizationCodeValue(authorizationCode.getToken().getTokenValue())
                  .authorizationCodeIssuedAt(authorizationCode.getToken().getIssuedAt())
                  .authorizationCodeExpiresAt(authorizationCode.getToken().getExpiresAt())
                  .authorizationCodeMetadata(writeMap(authorizationCode.getMetadata()));
        }
        
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getToken(OAuth2AccessToken.class);
        if (accessToken != null) {
            builder.accessTokenValue(accessToken.getToken().getTokenValue())
                  .accessTokenIssuedAt(accessToken.getToken().getIssuedAt())
                  .accessTokenExpiresAt(accessToken.getToken().getExpiresAt())
                  .accessTokenMetadata(writeMap(accessToken.getMetadata()))
                  .accessTokenType(accessToken.getToken().getTokenType().getValue())
                  .accessTokenScopes(accessToken.getToken().getScopes() != null ? 
                      String.join(" ", accessToken.getToken().getScopes()) : null);
        }
        
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getToken(OAuth2RefreshToken.class);
        if (refreshToken != null) {
            builder.refreshTokenValue(refreshToken.getToken().getTokenValue())
                  .refreshTokenIssuedAt(refreshToken.getToken().getIssuedAt())
                  .refreshTokenExpiresAt(refreshToken.getToken().getExpiresAt())
                  .refreshTokenMetadata(writeMap(refreshToken.getMetadata()));
        }
        
        OAuth2Authorization.Token<OidcIdToken> oidcIdToken = authorization.getToken(OidcIdToken.class);
        if (oidcIdToken != null) {
            builder.oidcIdTokenValue(oidcIdToken.getToken().getTokenValue())
                  .oidcIdTokenIssuedAt(oidcIdToken.getToken().getIssuedAt())
                  .oidcIdTokenExpiresAt(oidcIdToken.getToken().getExpiresAt())
                  .oidcIdTokenMetadata(writeMap(oidcIdToken.getMetadata()))
                  .oidcTokenClaims(writeMap(oidcIdToken.getClaims()));
        }
        
        return builder.build();
    }
    
    private OAuth2Authorization mapToAuthorization(Oauth2Authorization entity) {
        RegisteredClient registeredClient = RegisteredClient.withId(entity.getRegisteredClientId())
            .clientId("temp")
            .clientSecret("temp")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .build();
        
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .id(entity.getId().toString())
            .principalName(entity.getPrincipalName())
            .authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantType()))
            .attributes(attrs -> attrs.putAll(parseMap(entity.getAttributes())));
        
        if (entity.getAuthorizationCodeValue() != null) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                entity.getAuthorizationCodeValue(),
                entity.getAuthorizationCodeIssuedAt(),
                entity.getAuthorizationCodeExpiresAt());
            builder.token(authorizationCode, metadata -> metadata.putAll(parseMap(entity.getAuthorizationCodeMetadata())));
        }
        
        if (entity.getAccessTokenValue() != null) {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                entity.getAccessTokenValue(),
                entity.getAccessTokenIssuedAt(),
                entity.getAccessTokenExpiresAt());
            builder.token(accessToken, metadata -> metadata.putAll(parseMap(entity.getAccessTokenMetadata())));
        }
        
        if (entity.getRefreshTokenValue() != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                entity.getRefreshTokenValue(),
                entity.getRefreshTokenIssuedAt(),
                entity.getRefreshTokenExpiresAt());
            builder.token(refreshToken, metadata -> metadata.putAll(parseMap(entity.getRefreshTokenMetadata())));
        }
        
        if (entity.getOidcIdTokenValue() != null) {
            OidcIdToken idToken = new OidcIdToken(
                entity.getOidcIdTokenValue(),
                entity.getOidcIdTokenIssuedAt(),
                entity.getOidcIdTokenExpiresAt(),
                parseMap(entity.getOidcTokenClaims())
            );
            builder.token(idToken, metadata -> metadata.putAll(parseMap(entity.getOidcIdTokenMetadata())));
        }
        
        return builder.build();
    }
    
    private String writeMap(Map<String, Object> data) {
        try {
            return objectMapper.writeValueAsString(data);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to write map to JSON", e);
        }
    }
    
    private Map<String, Object> parseMap(String data) {
        if (data == null || data.isEmpty()) {
            return Collections.emptyMap();
        }
        try {
            return objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {});
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to parse map from JSON", e);
        }
    }
}
