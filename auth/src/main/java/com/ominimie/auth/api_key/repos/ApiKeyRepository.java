package com.ominimie.auth.api_key.repos;

import com.ominimie.auth.api_key.domain.ApiKey;
import java.util.UUID;
import org.springframework.data.mongodb.repository.MongoRepository;


public interface ApiKeyRepository extends MongoRepository<ApiKey, Long> {

    ApiKey findFirstByUserId(UUID id);

    boolean existsByKeyIgnoreCase(String key);

}
