package com.ominimie.auth.api_key.repos;

import com.ominimie.auth.api_key.domain.ApiKey;
import com.ominimie.auth.service.PrimarySequenceService;
import org.springframework.data.mongodb.core.mapping.event.AbstractMongoEventListener;
import org.springframework.data.mongodb.core.mapping.event.BeforeConvertEvent;
import org.springframework.stereotype.Component;


@Component
public class ApiKeyListener extends AbstractMongoEventListener<ApiKey> {

    private final PrimarySequenceService primarySequenceService;

    public ApiKeyListener(final PrimarySequenceService primarySequenceService) {
        this.primarySequenceService = primarySequenceService;
    }

    @Override
    public void onBeforeConvert(final BeforeConvertEvent<ApiKey> event) {
        if (event.getSource().getId() == null) {
            event.getSource().setId(primarySequenceService.getNextValue());
        }
    }

}
