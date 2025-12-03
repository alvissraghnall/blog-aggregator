package com.ominimie.auth.refresh_token.domain;

import com.ominimie.auth.user.domain.User;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.UUID;

@Document("refreshTokens")
@Getter
@Setter
public class RefreshToken {
    @Id
    private String id;
    
    @DBRef
    private User user;
    
    private Instant expiresAt;
    
    private Instant createdAt;
    
    private boolean revoked = false;
    
    private String createdBy; // IP address, device ID, ...
    
    public RefreshToken() {
        this.createdAt = Instant.now();
    }
    
    public RefreshToken(String token, User user, Instant expiresAt, String createdBy) {
        this();
        this.id = token;
        this.user = user;
        this.expiresAt = expiresAt;
        this.createdBy = createdBy;
    }
    
    public boolean isExpired() {
        return expiresAt != null && expiresAt.isBefore(Instant.now());
    }
}
