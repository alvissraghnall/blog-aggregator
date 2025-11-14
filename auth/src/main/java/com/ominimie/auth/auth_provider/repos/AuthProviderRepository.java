package com.ominimie.auth.auth_provider.repos;

import com.ominimie.auth.auth_provider.domain.AuthProvider;
import com.ominimie.auth.auth_provider.model.ProviderType;
import com.ominimie.auth.user.domain.User;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.mongodb.repository.MongoRepository;


public interface AuthProviderRepository extends MongoRepository<AuthProvider, Long> {

    AuthProvider findFirstByUserId(UUID id);

    Optional<AuthProvider> findByUserAndProvider(User user, ProviderType provider);

    List<AuthProvider> findByUser(User user);

}
