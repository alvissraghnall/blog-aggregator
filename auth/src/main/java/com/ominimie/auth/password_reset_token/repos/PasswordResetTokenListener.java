package com.ominimie.auth.password_reset_token.repos;

import com.ominimie.auth.password_reset_token.domain.PasswordResetToken;
import com.ominimie.auth.service.PrimarySequenceService;
import org.springframework.data.mongodb.core.mapping.event.AbstractMongoEventListener;
import org.springframework.data.mongodb.core.mapping.event.BeforeConvertEvent;
import org.springframework.stereotype.Component;


@Component
public class PasswordResetTokenListener extends AbstractMongoEventListener<PasswordResetToken> {

    private final PrimarySequenceService primarySequenceService;

    public PasswordResetTokenListener(final PrimarySequenceService primarySequenceService) {
        this.primarySequenceService = primarySequenceService;
    }

    @Override
    public void onBeforeConvert(final BeforeConvertEvent<PasswordResetToken> event) {
        if (event.getSource().getId() == null) {
            event.getSource().setId(primarySequenceService.getNextValue());
        }
    }

}
