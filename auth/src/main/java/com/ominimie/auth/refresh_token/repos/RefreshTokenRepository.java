package com.ominimie.auth.refresh_token.repos;

import com.ominimie.auth.refresh_token.domain.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.time.Instant;

@Repository
public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {
    
    Optional<RefreshToken> findByIdAndRevokedFalse(String id);
    
    List<RefreshToken> findByUserIdAndRevokedFalse(UUID userId);
    
    void deleteByExpiresAtBefore(Instant now);
}
