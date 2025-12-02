package com.ominimie.preferences.profile.repos;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.mongodb.repository.MongoRepository;

import com.ominimie.auth.user.domain.User;
import com.ominimie.preferences.profile.domain.UserProfile;

public interface UserProfileRepository extends MongoRepository<UserProfile, UUID> {

    Optional<UserProfile> findById(String id);

}
