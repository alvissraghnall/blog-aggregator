package com.ominimie.auth.oauth2_authorization.repos;

import com.ominimie.auth.oauth2_authorization.domain.Oauth2Authorization;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface Oauth2AuthorizationRepository extends MongoRepository<Oauth2Authorization, Long> {
    Optional<Oauth2Authorization> findByState(String state);
    Optional<Oauth2Authorization> findByAuthorizationCodeValue(String authorizationCode);
    Optional<Oauth2Authorization> findByAccessTokenValue(String accessToken);
    Optional<Oauth2Authorization> findByRefreshTokenValue(String refreshToken);
    Optional<Oauth2Authorization> findByOidcIdTokenValue(String idToken);
    List<Oauth2Authorization> findByPrincipalName(String principalName);
    long deleteByAccessTokenExpiresAtBefore(Instant expiresAt);
    long deleteByRefreshTokenExpiresAtBefore(Instant expiresAt);
}
