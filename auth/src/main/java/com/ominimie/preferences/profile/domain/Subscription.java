package com.ominimie.preferences.profile.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Subscription {

    private SubscriptionTier tier = SubscriptionTier.FREE;

    private SubscriptionStatus status = SubscriptionStatus.ACTIVE;

    // Nullable if lifetime or free
    private OffsetDateTime validUntil;

    public enum SubscriptionTier {
        FREE,
        PRO,
    }

    public enum SubscriptionStatus {
        ACTIVE,
        PAUSED,
        CANCELLED,
        EXPIRED
    }
}
