package com.ominimie.auth.config;

import java.time.Instant;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.ominimie.auth.oauth2_authorization.repos.Oauth2AuthorizationRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class TokenCleanupTask {

    private final Oauth2AuthorizationRepository authorizationRepository;

    @Scheduled(cron = "0 0 2 * * ?")
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        
        long deletedAccessTokens = authorizationRepository.deleteByAccessTokenExpiresAtBefore(now);
        log.info("Deleted {} expired access tokens", deletedAccessTokens);
        
        long deletedRefreshTokens = authorizationRepository.deleteByRefreshTokenExpiresAtBefore(now);
        log.info("Deleted {} expired refresh tokens", deletedRefreshTokens);
    }
}
