package com.ominimie.auth.auth_provider.service;

import com.ominimie.auth.auth_provider.domain.AuthProvider;
import com.ominimie.auth.auth_provider.repos.AuthProviderRepository;
import com.ominimie.auth.events.BeforeDeleteUser;
import com.ominimie.auth.util.ReferencedException;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;


@Service
public class AuthProviderService {

    private final AuthProviderRepository authProviderRepository;

    public AuthProviderService(final AuthProviderRepository authProviderRepository) {
        this.authProviderRepository = authProviderRepository;
    }

    @EventListener(BeforeDeleteUser.class)
    public void on(final BeforeDeleteUser event) {
        final ReferencedException referencedException = new ReferencedException();
        final AuthProvider userAuthProvider = authProviderRepository.findFirstByUserId(event.getId());
        if (userAuthProvider != null) {
            referencedException.setKey("user.authProvider.user.referenced");
            referencedException.addParam(userAuthProvider.getId());
            throw referencedException;
        }
    }

}
