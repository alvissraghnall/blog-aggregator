package com.ominimie.auth.email_verification.domain;

import com.ominimie.auth.user.domain.User;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.UUID;

@Document("emailVerificationTokens")
@Getter
@Setter
public class EmailVerificationToken {
    @Id
    private String id;
    
    @DBRef
    private User user;
    
    private Instant expiresAt;
    
    private Instant createdAt;
    
    private boolean used = false;
    
    public EmailVerificationToken() {
        this.createdAt = Instant.now();
    }
    
    public EmailVerificationToken(String token, User user, Instant expiresAt) {
        this();
        this.id = token;
        this.user = user;
        this.expiresAt = expiresAt;
    }
    
    public boolean isExpired() {
        return expiresAt != null && expiresAt.isBefore(Instant.now());
    }
}
