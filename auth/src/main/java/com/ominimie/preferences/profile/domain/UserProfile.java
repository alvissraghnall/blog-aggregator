package com.ominimie.preferences.profile.domain;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.OffsetDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Document("user_profiles")
@Getter
@Setter
public class UserProfile {

    @Id
    private UUID userId;

    // E.g., "Tech", "Crypto", "Java"
    private Set<String> interestTags = new HashSet<>();

    // Specific blogs they want to track, e.g., "https://blog.wikiwiki.com"
    private Set<String> followedBlogUrls = new HashSet<>();

    private EmailPreferences emailPreferences;

    private Subscription subscription;

    @CreatedDate
    private OffsetDateTime dateCreated;

    @LastModifiedDate
    private OffsetDateTime lastUpdated;

    @Version
    private Integer version;
}
