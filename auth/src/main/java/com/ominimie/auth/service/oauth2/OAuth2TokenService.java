package com.ominimie.auth.service.oauth2;

import java.security.Principal;
import java.time.Instant;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Service;

import com.ominimie.auth.user.domain.CustomUserDetails;
import com.ominimie.auth.user.domain.User;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class OAuth2TokenService {

    private final OAuth2AuthorizationService authorizationService;
    
    private final OAuth2TokenGenerator<?> tokenGenerator;
    
    private final RegisteredClientRepository registeredClientRepository;
    
    private final AuthenticationManager authenticationManager;

    public OAuth2TokenResponse generateTokens(String username, String password) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password)
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        RegisteredClient registeredClient = registeredClientRepository
            .findByClientId("backend-service");

        OAuth2TokenContext tokenContext = createTokenContext(
            authentication, 
            registeredClient,
            OAuth2TokenType.ACCESS_TOKEN
        );

        OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);
        
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.getTokenValue(),
            generatedAccessToken.getIssuedAt(),
            generatedAccessToken.getExpiresAt(),
            tokenContext.getAuthorizedScopes()
        );

        OAuth2TokenContext refreshTokenContext = createTokenContext(
            authentication,
            registeredClient,
            OAuth2TokenType.REFRESH_TOKEN
        );
        
        OAuth2Token generatedRefreshToken = tokenGenerator.generate(refreshTokenContext);
        
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
            generatedRefreshToken.getTokenValue(),
            generatedRefreshToken.getIssuedAt(),
            generatedRefreshToken.getExpiresAt()
        );

        OAuth2Authorization authorization = OAuth2Authorization
            .withRegisteredClient(registeredClient)
            .principalName(authentication.getName())
            .authorizationGrantType(AuthorizationGrantType.PASSWORD)
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .attribute(Principal.class.getName(), authentication)
            .build();

        authorizationService.save(authorization);

        return new OAuth2TokenResponse(accessToken, refreshToken);
    }

	public OAuth2TokenResponse generateTokensForOAuthUser(User user) {
        UserDetails userDetails = new CustomUserDetails(user, null);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
            userDetails, null, userDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);

        RegisteredClient registeredClient = registeredClientRepository
            .findByClientId("backend-service");

        OAuth2TokenContext tokenContext = createTokenContext(
            authentication,
            registeredClient,
            OAuth2TokenType.ACCESS_TOKEN
        );

        OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.getTokenValue(),
            generatedAccessToken.getIssuedAt(),
            generatedAccessToken.getExpiresAt(),
            tokenContext.getAuthorizedScopes()
        );

        OAuth2TokenContext refreshTokenContext = createTokenContext(
            authentication,
            registeredClient,
            OAuth2TokenType.REFRESH_TOKEN
        );

        OAuth2Token generatedRefreshToken = tokenGenerator.generate(refreshTokenContext);

        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
            generatedRefreshToken.getTokenValue(),
            generatedRefreshToken.getIssuedAt(),
            generatedRefreshToken.getExpiresAt()
        );

        OAuth2Authorization authorization = OAuth2Authorization
            .withRegisteredClient(registeredClient)
            .principalName(authentication.getName())
            .authorizationGrantType(AuthorizationGrantType.PASSWORD)
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .attribute(Principal.class.getName(), authentication)
            .build();

        authorizationService.save(authorization);

        return new OAuth2TokenResponse(accessToken, refreshToken);
    }

    public OAuth2TokenResponse refreshToken(String refreshTokenValue) {
        OAuth2Authorization authorization = authorizationService
            .findByToken(refreshTokenValue, OAuth2TokenType.REFRESH_TOKEN);

        if (authorization == null) {
            throw new OAuth2AuthenticationException("Invalid refresh token");
        }

        RegisteredClient registeredClient = registeredClientRepository
            .findById(authorization.getRegisteredClientId());

        Authentication principal = authorization.getAttribute(Principal.class.getName());

        OAuth2TokenContext tokenContext = createTokenContext(
            principal,
            registeredClient,
            OAuth2TokenType.ACCESS_TOKEN
        );

        OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);
        
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.getTokenValue(),
            generatedAccessToken.getIssuedAt(),
            generatedAccessToken.getExpiresAt(),
            tokenContext.getAuthorizedScopes()
        );

        OAuth2Authorization updatedAuthorization = OAuth2Authorization
            .from(authorization)
            .accessToken(accessToken)
            .build();

        authorizationService.save(updatedAuthorization);

        return new OAuth2TokenResponse(accessToken, authorization.getRefreshToken().getToken());
    }

    public OAuth2TokenIntrospection introspectToken(String token) {
        OAuth2Authorization authorization = authorizationService
            .findByToken(token, OAuth2TokenType.ACCESS_TOKEN);

        if (authorization == null) {
            return new OAuth2TokenIntrospection(false, null);
        }

        OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
        
        if (accessToken.getExpiresAt() != null && 
            accessToken.getExpiresAt().isBefore(Instant.now())) {
            return new OAuth2TokenIntrospection(false, null);
        }

        CustomUserDetails userDetails = (CustomUserDetails) authorization
            .getAttribute(Principal.class.getName());

        return new OAuth2TokenIntrospection(true, userDetails.getUser());
    }

    private OAuth2TokenContext createTokenContext(
            Authentication authentication,
            RegisteredClient registeredClient,
            OAuth2TokenType tokenType) {
        
        return DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(authentication)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .tokenType(tokenType)
            .authorizationGrantType(AuthorizationGrantType.PASSWORD)
            .authorizedScopes(registeredClient.getScopes())
            .build();
    }
}
