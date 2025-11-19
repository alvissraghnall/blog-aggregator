package com.ominimie.auth;

import com.ominimie.auth.api_key.repos.ApiKeyRepository;
import com.ominimie.auth.auth_provider.repos.AuthProviderRepository;
import com.ominimie.auth.user.repos.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.grpc.client.ImportGrpcClients;
import org.springframework.grpc.test.AutoConfigureInProcessTransport;
import org.springframework.test.context.ActiveProfiles;

import com.icegreen.greenmail.configuration.GreenMailConfiguration;
import com.icegreen.greenmail.junit5.GreenMailExtension;
import com.icegreen.greenmail.util.ServerSetupTest;
import com.ominimie.auth.email_verification.repos.EmailVerificationTokenRepository;
import com.ominimie.auth.refresh_token.repos.RefreshTokenRepository;
import org.junit.jupiter.api.extension.RegisterExtension;


@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureInProcessTransport
public abstract class AbstractIntegrationTest {

    @RegisterExtension
    protected static GreenMailExtension greenMail = new GreenMailExtension(ServerSetupTest.SMTP)
            .withConfiguration(GreenMailConfiguration.aConfig().withUser("xavier", "godofwar"))
            .withPerMethodLifecycle(true);

    @Autowired
    protected UserRepository userRepository;

    @Autowired
    protected ApiKeyRepository apiKeyRepository;

    @Autowired
    protected AuthProviderRepository authProviderRepository;

    @Autowired
    protected EmailVerificationTokenRepository emailVerificationTokenRepository;
    
    @Autowired
    protected RefreshTokenRepository refreshTokenRepository;

    @BeforeEach
    void setupDatabase() {
        userRepository.deleteAll();
        apiKeyRepository.deleteAll();
        authProviderRepository.deleteAll();
        emailVerificationTokenRepository.deleteAll();
        refreshTokenRepository.deleteAll();
    }
    
    @TestConfiguration
    @ImportGrpcClients(basePackageClasses = AuthApplication.class)
    static class TestConfig {
    }
}
