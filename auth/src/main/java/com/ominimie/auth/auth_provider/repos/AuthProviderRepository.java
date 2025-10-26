package com.ominimie.auth.auth_provider.repos;

import com.ominimie.auth.auth_provider.domain.AuthProvider;
import java.util.UUID;
import org.springframework.data.mongodb.repository.MongoRepository;


public interface AuthProviderRepository extends MongoRepository<AuthProvider, Long> {

    AuthProvider findFirstByUserId(UUID id);

}
