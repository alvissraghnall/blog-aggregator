package com.ominimie.auth.email_verification.repos;

import com.ominimie.auth.email_verification.domain.EmailVerificationToken;
import com.ominimie.auth.user.domain.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.time.Instant;

public interface EmailVerificationTokenRepository extends MongoRepository<EmailVerificationToken, String> {
    
    Optional<EmailVerificationToken> findByIdAndUsedFalse(String id);

    Optional<EmailVerificationToken> findByUser(User user);
    
    void deleteByExpiresAtBefore(Instant now);

    void deleteAllByUser(User user);
}
