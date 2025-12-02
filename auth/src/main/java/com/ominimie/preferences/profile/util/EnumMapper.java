package com.ominimie.preferences.profile.util;

import org.mapstruct.EnumMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Named;
import org.mapstruct.ValueMapping;
import com.ominimie.preferences.profile.domain.EmailPreferences;
import com.ominimie.preferences.profile.domain.Subscription;

@Mapper(componentModel = "spring")
public interface EnumMapper {

    @ValueMapping(source = "REAL_TIME", target = "FREQUENCY_REAL_TIME")
    @ValueMapping(source = "DAILY",     target = "FREQUENCY_DAILY")
    @ValueMapping(source = "WEEKLY",    target = "FREQUENCY_WEEKLY")
    @ValueMapping(source = "PAUSED",    target = "FREQUENCY_PAUSED")
    com.ominimie.preferences.proto.Frequency
        toProto(EmailPreferences.Frequency freq);

    @ValueMapping(source = "FREQUENCY_REAL_TIME", target = "REAL_TIME")
    @ValueMapping(source = "FREQUENCY_DAILY",     target = "DAILY")
    @ValueMapping(source = "FREQUENCY_WEEKLY",    target = "WEEKLY")
    @ValueMapping(source = "FREQUENCY_PAUSED",    target = "PAUSED")
    @ValueMapping(source = "UNRECOGNIZED",        target = "PAUSED")
    EmailPreferences.Frequency
        toDomain(com.ominimie.preferences.proto.Frequency freq);

    @ValueMapping(source = "FREE", target = "TIER_FREE")
    @ValueMapping(source = "PRO",  target = "TIER_PRO")
    com.ominimie.preferences.proto.SubscriptionTier
        toProto(Subscription.SubscriptionTier tier);

    @ValueMapping(source = "TIER_FREE",      target = "FREE")
    @ValueMapping(source = "TIER_PRO",       target = "PRO")
    @ValueMapping(source = "UNRECOGNIZED",   target = "FREE")
    Subscription.SubscriptionTier
        toDomain(com.ominimie.preferences.proto.SubscriptionTier tier);


    @ValueMapping(source = "ACTIVE",   target = "STATUS_ACTIVE")
    @ValueMapping(source = "PAUSED",   target = "STATUS_PAUSED")
    @ValueMapping(source = "CANCELLED",target = "STATUS_CANCELLED")
    @ValueMapping(source = "EXPIRED",  target = "STATUS_EXPIRED")
    com.ominimie.preferences.proto.SubscriptionStatus
        toProto(Subscription.SubscriptionStatus status);

    @ValueMapping(source = "STATUS_ACTIVE",    target = "ACTIVE")
    @ValueMapping(source = "STATUS_PAUSED",    target = "PAUSED")
    @ValueMapping(source = "STATUS_CANCELLED", target = "CANCELLED")
    @ValueMapping(source = "STATUS_EXPIRED",   target = "EXPIRED")
    @ValueMapping(source = "UNRECOGNIZED",     target = "EXPIRED")
    Subscription.SubscriptionStatus
        toDomain(com.ominimie.preferences.proto.SubscriptionStatus status);
}
