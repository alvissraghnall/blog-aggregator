package com.ominimie.preferences.profile.util;

import com.google.protobuf.Timestamp;
import com.ominimie.preferences.profile.domain.EmailPreferences;
import com.ominimie.preferences.profile.domain.Subscription;
import com.ominimie.preferences.profile.domain.UserProfile;
import com.ominimie.preferences.proto.UserProfileResponse;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

import java.time.Instant;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

@Mapper(
    componentModel = "spring",
    uses = {
        ProfileMapper.Helper.class,
        EnumMapper.class
    }
)
public interface ProfileMapper {

    @Mapping(target = "userId", source = "userId", qualifiedByName = "uuidToString")
    @Mapping(target = "dateCreated", source = "dateCreated", qualifiedByName = "offsetToTimestamp")
    @Mapping(target = "lastUpdated", source = "lastUpdated", qualifiedByName = "offsetToTimestamp")
    UserProfileResponse toProto(UserProfile domain);

    @Mapping(target = "preferredTime", source = "preferredTime", qualifiedByName = "localTimeToString")
    com.ominimie.preferences.proto.EmailPreferences toProto(EmailPreferences domain);

    @Mapping(target = "validUntil", source = "validUntil", qualifiedByName = "offsetToTimestamp")
    com.ominimie.preferences.proto.Subscription toProto(Subscription domain);


    @Mapping(target = "preferredTime", source = "preferredTime", qualifiedByName = "stringToLocalTime")
    EmailPreferences toDomain(com.ominimie.preferences.proto.EmailPreferences proto);

    @Mapping(target = "validUntil", source = "validUntil", qualifiedByName = "timestampToOffset")
    Subscription toDomain(com.ominimie.preferences.proto.Subscription proto);

    @Mapping(target = "userId", source = "userId", qualifiedByName = "stringToUuid")
    @Mapping(target = "dateCreated", source = "dateCreated", qualifiedByName = "timestampToOffset")
    @Mapping(target = "lastUpdated", source = "lastUpdated", qualifiedByName = "timestampToOffset")
    UserProfile toDomain(UserProfileResponse proto);

    class Helper {

        @Named("uuidToString")
        public String uuidToString(UUID uuid) {
            return uuid == null ? null : uuid.toString();
        }

        @Named("stringToUuid")
        public UUID stringToUuid(String uuid) {
            return (uuid == null || uuid.isEmpty()) ? null : UUID.fromString(uuid);
        }

        @Named("offsetToTimestamp")
        public Timestamp offsetToTimestamp(OffsetDateTime odt) {
            if (odt == null) return null;

            Instant instant = odt.toInstant();
            return Timestamp.newBuilder()
                    .setSeconds(instant.getEpochSecond())
                    .setNanos(instant.getNano())
                    .build();
        }

        @Named("timestampToOffset")
        public OffsetDateTime timestampToOffset(Timestamp ts) {
            if (ts == null) return null;

            Instant instant = Instant.ofEpochSecond(ts.getSeconds(), ts.getNanos());
            return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
        }

        private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

        @Named("localTimeToString")
        public String localTimeToString(LocalTime time) {
            return time == null ? null : time.format(TIME_FMT);
        }

        @Named("stringToLocalTime")
        public LocalTime stringToLocalTime(String timeString) {
            return (timeString == null || timeString.isEmpty())
                    ? null
                    : LocalTime.parse(timeString, TIME_FMT);
        }

        @Named("timestampToOffset")
        default OffsetDateTime timestampToOffset(com.google.protobuf.Timestamp timestamp) {
            if (timestamp == null || timestamp.getSeconds() == 0) return null;
            return OffsetDateTime.ofInstant(
                Instant.ofEpochSecond(timestamp.getSeconds(), timestamp.getNanos()), 
                ZoneId.systemDefault()
            );
        }

    }
}
