package com.ominimie.auth.password_reset_token.service;

import com.ominimie.auth.events.BeforeDeleteUser;
import com.ominimie.auth.password_reset_token.domain.PasswordResetToken;
import com.ominimie.auth.password_reset_token.repos.PasswordResetTokenRepository;
import com.ominimie.auth.util.ReferencedException;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;


@Service
public class PasswordResetTokenService {

    private final PasswordResetTokenRepository passwordResetTokenRepository;

    public PasswordResetTokenService(
            final PasswordResetTokenRepository passwordResetTokenRepository) {
        this.passwordResetTokenRepository = passwordResetTokenRepository;
    }

    @EventListener(BeforeDeleteUser.class)
    public void on(final BeforeDeleteUser event) {
        final ReferencedException referencedException = new ReferencedException();
        final PasswordResetToken userPasswordResetToken = passwordResetTokenRepository.findFirstByUserId(event.getId());
        if (userPasswordResetToken != null) {
            referencedException.setKey("user.passwordResetToken.user.referenced");
            referencedException.addParam(userPasswordResetToken.getId());
            throw referencedException;
        }
    }

}
