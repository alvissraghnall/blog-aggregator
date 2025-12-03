package com.ominimie.auth.auth_provider.repos;

import com.ominimie.auth.auth_provider.domain.AuthProvider;
import com.ominimie.auth.proto.ProviderType;
import com.ominimie.auth.user.domain.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;
import java.util.Optional;

public interface AuthProviderRepository extends MongoRepository<AuthProvider, Long> {
    AuthProvider findFirstByUserId(UUID userId);

    List<AuthProvider> findByUser(User user);
    
    Optional<AuthProvider> findByUserAndProvider(User user, ProviderType provider);
    
    boolean existsByUserAndProvider(User user, ProviderType provider);
    
    Optional<AuthProvider> findByProviderAndProviderUserId(ProviderType provider, String providerUserId);
}
