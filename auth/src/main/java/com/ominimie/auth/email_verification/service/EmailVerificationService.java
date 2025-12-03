package com.ominimie.auth.email_verification.service;

import com.ominimie.auth.email_verification.domain.EmailVerificationToken;
import com.ominimie.auth.email_verification.repos.EmailVerificationTokenRepository;
import com.ominimie.auth.service.EmailService;
import com.ominimie.auth.user.domain.User;
import com.ominimie.auth.user.repos.UserRepository;
import io.grpc.Status;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {
    
    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    
    private static final int TOKEN_LENGTH = 32;
    private static final SecureRandom secureRandom = new SecureRandom();
    
    public String generateVerificationToken(User user) {
        tokenRepository.findByUser(user).ifPresent(token -> {
            token.setUsed(true);
            tokenRepository.save(token);
        });
        
        String tokenValue = generateToken();
        Instant expiresAt = Instant.now().plus(24, ChronoUnit.HOURS);
        
        EmailVerificationToken token = new EmailVerificationToken(tokenValue, user, expiresAt);
        tokenRepository.save(token);
        
        emailService.sendVerificationEmail(user.getEmail(), tokenValue);
        
        return tokenValue;
    }
    
    public User verifyToken(String token) {
        EmailVerificationToken verificationToken = tokenRepository.findByIdAndUsedFalse(token)
                .orElseThrow(() -> Status.NOT_FOUND
                        .withDescription("Invalid or expired verification token")
                        .asRuntimeException());
        
        if (verificationToken.isExpired()) {
            throw Status.PERMISSION_DENIED
                    .withDescription("Verification token has expired")
                    .asRuntimeException();
        }
        
        verificationToken.setUsed(true);
        tokenRepository.save(verificationToken);
        
        User user = verificationToken.getUser();
        user.setEmailVerified(true);
        return userRepository.save(user);
    }

    public void deleteExistingTokensForUser (User user) {
        tokenRepository.deleteAllByUser(user);
    }
    
    private String generateToken() {
        byte[] tokenBytes = new byte[TOKEN_LENGTH];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }
}
