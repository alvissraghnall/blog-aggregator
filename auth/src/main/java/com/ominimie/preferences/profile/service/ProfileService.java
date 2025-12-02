package com.ominimie.preferences.profile.service;

import com.ominimie.preferences.profile.domain.UserProfile;
import com.ominimie.preferences.profile.domain.EmailPreferences;
import com.ominimie.preferences.profile.domain.Subscription;
import java.util.Set;
import java.util.UUID;

public interface ProfileService {
    
    UserProfile addInterestTags(UUID userId, Set<String> tags);

    UserProfile removeInterestTags(UUID userId, Set<String> tags);

    UserProfile followBlogs(UUID userId, Set<String> blogs);

    UserProfile unfollowBlogs(UUID userId, Set<String> blogs);

    UserProfile updateEmailPreferences(UUID userId, EmailPreferences emailPrefs);
    
    UserProfile getProfile(UUID userId);
    
    void initProfileOnRegister(UUID userId);

    // Admin-facing update
    UserProfile updateSubscription(UUID userId, Subscription subscription);
}
