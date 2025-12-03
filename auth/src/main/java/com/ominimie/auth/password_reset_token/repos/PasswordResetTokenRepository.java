package com.ominimie.auth.password_reset_token.repos;

import com.ominimie.auth.password_reset_token.domain.PasswordResetToken;
import java.util.UUID;
import org.springframework.data.mongodb.repository.MongoRepository;


public interface PasswordResetTokenRepository extends MongoRepository<PasswordResetToken, Long> {

    PasswordResetToken findFirstByUserId(UUID id);

}
