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

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureInProcessTransport
public abstract class AbstractIntegrationTest {

    @Autowired
    protected UserRepository userRepository;

    @Autowired
    protected ApiKeyRepository apiKeyRepository;

    @Autowired
    protected AuthProviderRepository authProviderRepository;

    @BeforeEach
    void setupDatabase() {
        userRepository.deleteAll();
        apiKeyRepository.deleteAll();
        authProviderRepository.deleteAll();
    }
    
    @TestConfiguration
    @ImportGrpcClients(basePackageClasses = AuthApplication.class)
    static class TestConfig {
    }
}

