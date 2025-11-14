package com.ominimie.auth.oauth2_authorization.repos;

import com.ominimie.auth.oauth2_authorization.domain.Oauth2Authorization;
import com.ominimie.auth.service.PrimarySequenceService;
import org.springframework.data.mongodb.core.mapping.event.AbstractMongoEventListener;
import org.springframework.data.mongodb.core.mapping.event.BeforeConvertEvent;
import org.springframework.stereotype.Component;

@Component
public class Oauth2AuthorizationListener extends AbstractMongoEventListener<Oauth2Authorization> {

    private final PrimarySequenceService primarySequenceService;

    public Oauth2AuthorizationListener(final PrimarySequenceService primarySequenceService) {
        this.primarySequenceService = primarySequenceService;
    }

    @Override
    public void onBeforeConvert(final BeforeConvertEvent<Oauth2Authorization> event) {
        if (event.getSource().getId() == null) {
            event.getSource().setId(primarySequenceService.getNextValue());
        }
    }
}
