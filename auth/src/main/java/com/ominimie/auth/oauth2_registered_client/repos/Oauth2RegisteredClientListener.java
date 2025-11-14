package com.ominimie.auth.oauth2_registered_client.repos;

import com.ominimie.auth.oauth2_registered_client.domain.Oauth2RegisteredClient;
import com.ominimie.auth.service.PrimarySequenceService;
import org.springframework.data.mongodb.core.mapping.event.AbstractMongoEventListener;
import org.springframework.data.mongodb.core.mapping.event.BeforeConvertEvent;
import org.springframework.stereotype.Component;


@Component
public class Oauth2RegisteredClientListener extends AbstractMongoEventListener<Oauth2RegisteredClient> {

    private final PrimarySequenceService primarySequenceService;

    public Oauth2RegisteredClientListener(final PrimarySequenceService primarySequenceService) {
        this.primarySequenceService = primarySequenceService;
    }

    @Override
    public void onBeforeConvert(final BeforeConvertEvent<Oauth2RegisteredClient> event) {
        if (event.getSource().getId() == null) {
            event.getSource().setId(primarySequenceService.getNextValue());
        }
    }

}
