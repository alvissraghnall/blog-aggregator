package com.ominimie.preferences.profile.service;

import com.ominimie.preferences.profile.domain.UserProfile;
import com.ominimie.preferences.profile.domain.EmailPreferences;
import com.ominimie.preferences.profile.domain.Subscription;
import com.ominimie.preferences.profile.repos.UserProfileRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;

import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class ProfileServiceImpl implements ProfileService {

    private final UserProfileRepository repository;

    private UserProfile getExistingProfile(UUID userId) {
        return repository.findById(userId)
                .orElseThrow(() -> new ProfileNotFoundException(userId));
    }

    @Transactional
    private UserProfile updateSet(UUID userId, Set<String> values, 
                                  java.util.function.Consumer<Set<String>> addOrRemove) {
        UserProfile profile = getExistingProfile(userId);
        addOrRemove.accept(values);
        return repository.save(profile);
    }

    @Override
    @Transactional
    public UserProfile addInterestTags(UUID userId, Set<String> tags) {
        return updateSet(userId, tags, profileTags -> {
            UserProfile profile = getExistingProfile(userId);
            profile.getInterestTags().addAll(profileTags);
        });
    }

    @Override
    @Transactional
    public UserProfile removeInterestTags(UUID userId, Set<String> tags) {
        return updateSet(userId, tags, profileTags -> {
            UserProfile profile = getExistingProfile(userId);
            profile.getInterestTags().removeAll(profileTags);
        });
    }

    @Override
    @Transactional
    public UserProfile followBlogs(UUID userId, Set<String> blogs) {
        return updateSet(userId, blogs, profileBlogs -> {
            UserProfile profile = getExistingProfile(userId);
            profile.getFollowedBlogUrls().addAll(profileBlogs);
        });
    }

    @Override
    @Transactional
    public UserProfile unfollowBlogs(UUID userId, Set<String> blogs) {
        return updateSet(userId, blogs, profileBlogs -> {
            UserProfile profile = getExistingProfile(userId);
            profile.getFollowedBlogUrls().removeAll(profileBlogs);
        });
    }

    @Override
    @Transactional
    public UserProfile updateEmailPreferences(UUID userId, EmailPreferences emailPrefs) {
        UserProfile profile = getExistingProfile(userId);
        profile.setEmailPreferences(emailPrefs);
        return repository.save(profile);
    }

    @Override
    @Transactional
    public UserProfile updateSubscription(UUID userId, Subscription subscription) {
        UserProfile profile = getExistingProfile(userId);
        profile.setSubscription(subscription);
        return repository.save(profile);
    }

    @Override
    @Transactional
    public UserProfile getProfile(UUID userId) {
        return repository.findById(userId)
                .orElseThrow(() -> new ProfileNotFoundException(userId));
    }

    public void initProfileOnRegister(UUID userId) {
        if (repository.existsById(userId)) return;

        UserProfile profile = new UserProfile();
        profile.setUserId(userId);
        profile.setEmailPreferences(EmailPreferences.builder()
                .frequency(EmailPreferences.Frequency.WEEKLY)
                .marketingEmailsEnabled(false)
                .build());
        profile.setSubscription(Subscription.builder()
                .tier(Subscription.SubscriptionTier.FREE)
                .status(Subscription.SubscriptionStatus.ACTIVE)
                .build());
        repository.save(profile);
    }

    public static class ProfileNotFoundException extends RuntimeException {
        public ProfileNotFoundException(UUID userId) {
            super("Profile not found for userId: " + userId);
        }
    }
}
