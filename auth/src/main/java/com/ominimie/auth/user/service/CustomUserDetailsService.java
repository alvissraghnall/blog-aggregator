package com.ominimie.auth.user.service;

import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.ominimie.auth.auth_provider.domain.AuthProvider;
import com.ominimie.auth.proto.ProviderType;
import com.ominimie.auth.auth_provider.repos.AuthProviderRepository;
import com.ominimie.auth.user.domain.CustomUserDetails;
import com.ominimie.auth.user.domain.User;
import com.ominimie.auth.user.repos.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    
    private final AuthProviderRepository authProviderRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        if (!user.getActive()) {
            throw new DisabledException("User account is inactive");
        }

        AuthProvider localProvider = authProviderRepository
            .findByUserAndProvider(user, ProviderType.LOCAL)
            .orElseThrow(() -> new UsernameNotFoundException("No local authentication method found"));

        return new CustomUserDetails(user, localProvider.getPasswordHash());
    }
}
