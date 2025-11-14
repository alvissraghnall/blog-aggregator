package com.ominimie.auth.oauth2_registered_client.repos;

import com.ominimie.auth.oauth2_registered_client.domain.Oauth2RegisteredClient;

import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

public interface Oauth2RegisteredClientRepository extends MongoRepository<Oauth2RegisteredClient, Long> {
    Optional<Oauth2RegisteredClient> findByClientId(String clientId);
    Optional<Oauth2RegisteredClient> findById(Long id);
    boolean existsByClientId(String clientId);
}
