package com.ominimie.auth.auth_provider.repos;

import com.ominimie.auth.auth_provider.domain.AuthProvider;
import com.ominimie.auth.service.PrimarySequenceService;
import org.springframework.data.mongodb.core.mapping.event.AbstractMongoEventListener;
import org.springframework.data.mongodb.core.mapping.event.BeforeConvertEvent;
import org.springframework.stereotype.Component;


@Component
public class AuthProviderListener extends AbstractMongoEventListener<AuthProvider> {

    private final PrimarySequenceService primarySequenceService;

    public AuthProviderListener(final PrimarySequenceService primarySequenceService) {
        this.primarySequenceService = primarySequenceService;
    }

    @Override
    public void onBeforeConvert(final BeforeConvertEvent<AuthProvider> event) {
        if (event.getSource().getId() == null) {
            event.getSource().setId(primarySequenceService.getNextValue());
        }
    }

}
