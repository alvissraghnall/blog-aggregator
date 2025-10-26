package com.ominimie.auth.user.repos;

import com.ominimie.auth.user.domain.User;
import java.util.UUID;
import org.springframework.data.mongodb.repository.MongoRepository;


public interface UserRepository extends MongoRepository<User, UUID> {

    boolean existsByEmailIgnoreCase(String email);

}
