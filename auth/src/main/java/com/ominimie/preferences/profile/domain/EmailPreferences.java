package com.ominimie.preferences.profile.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalTime;
import java.time.ZoneId;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailPreferences {

    private Frequency frequency = Frequency.WEEKLY;

    private LocalTime preferredTime;
    
    private String timezone; // e.g., "Africa/Lagos"

    private boolean marketingEmailsEnabled;

    public enum Frequency {
        REAL_TIME,
        DAILY,
        WEEKLY,
        PAUSED
    }
}
