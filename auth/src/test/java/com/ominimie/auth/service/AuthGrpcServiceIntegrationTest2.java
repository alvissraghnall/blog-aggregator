package com.ominimie.auth.service;

import com.ominimie.auth.config.TestSecurityConfig;
import com.ominimie.auth.proto.*;
import com.ominimie.auth.user.repos.UserRepository;
import io.grpc.Metadata;
import io.grpc.stub.MetadataUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Import(TestSecurityConfig.class)
public class AuthGrpcServiceIntegrationTest2 {

    @Autowired
    private UserRepository userRepository;

	private AuthServiceGrpc.AuthServiceBlockingStub blockingStub;

    @BeforeEach
    void setUp() throws Exception {
        userRepository.deleteAll();
        
    }

    @Test
    void testRegisterAndLogin_Success() {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
            .setEmail("test@example.com")
            .setPassword("password123")
            .setFullName("Test User")
            .build();

        AuthResponse registerResponse = blockingStub.register(registerRequest);
        
        assertNotNull(registerResponse);
        assertNotNull(registerResponse.getAccessToken());
        assertNotNull(registerResponse.getRefreshToken());
        assertEquals("test@example.com", registerResponse.getUser().getEmail());
        assertEquals("Test User", registerResponse.getUser().getFullName());
        assertTrue(registerResponse.getUser().getActive());

        LoginRequest loginRequest = LoginRequest.newBuilder()
            .setEmail("test@example.com")
            .setPassword("password123")
            .build();

        AuthResponse loginResponse = blockingStub.login(loginRequest);
        
        assertNotNull(loginResponse);
        assertNotNull(loginResponse.getAccessToken());
        assertNotNull(loginResponse.getRefreshToken());
        assertEquals("test@example.com", loginResponse.getUser().getEmail());
    }

    @Test
    void testRegister_EmailAlreadyExists() {
        RegisterRequest request = RegisterRequest.newBuilder()
            .setEmail("duplicate@example.com")
            .setPassword("password123")
            .setFullName("First User")
            .build();

        blockingStub.register(request);

        RegisterRequest duplicateRequest = RegisterRequest.newBuilder()
            .setEmail("duplicate@example.com")
            .setPassword("differentpassword")
            .setFullName("Second User")
            .build();

        assertThrows(io.grpc.StatusRuntimeException.class, () -> {
            blockingStub.register(duplicateRequest);
        });
    }

    @Test
    void testLogin_InvalidCredentials() {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
            .setEmail("user@example.com")
            .setPassword("correctpassword")
            .setFullName("Test User")
            .build();

        blockingStub.register(registerRequest);

        LoginRequest loginRequest = LoginRequest.newBuilder()
            .setEmail("user@example.com")
            .setPassword("wrongpassword")
            .build();

        assertThrows(io.grpc.StatusRuntimeException.class, () -> {
            blockingStub.login(loginRequest);
        });
    }

    @Test
    void testRefreshToken_Success() {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
            .setEmail("refresh@example.com")
            .setPassword("password123")
            .setFullName("Refresh User")
            .build();

        AuthResponse registerResponse = blockingStub.register(registerRequest);
        String refreshToken = registerResponse.getRefreshToken();

        RefreshTokenRequest refreshRequest = RefreshTokenRequest.newBuilder()
            .setRefreshToken(refreshToken)
            .build();

        AuthResponse refreshResponse = blockingStub.refreshToken(refreshRequest);
        
        assertNotNull(refreshResponse);
        assertNotNull(refreshResponse.getAccessToken());
        assertNotNull(refreshResponse.getRefreshToken());
    }

    @Test
    void testValidateToken_SuccessAndFailure() {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
            .setEmail("validate@example.com")
            .setPassword("password123")
            .setFullName("Validate User")
            .build();

        AuthResponse registerResponse = blockingStub.register(registerRequest);
        String accessToken = registerResponse.getAccessToken();

        ValidateTokenRequest validateRequest = ValidateTokenRequest.newBuilder()
            .setToken(accessToken)
            .build();

        ValidateTokenResponse validateResponse = blockingStub.validateToken(validateRequest);
        
        assertTrue(validateResponse.getValid());
        assertEquals("validate@example.com", validateResponse.getUser().getEmail());

        ValidateTokenRequest invalidRequest = ValidateTokenRequest.newBuilder()
            .setToken("invalid.token.here")
            .build();

        ValidateTokenResponse invalidResponse = blockingStub.validateToken(invalidRequest);
        
        assertFalse(invalidResponse.getValid());
        assertFalse(invalidResponse.getError().isEmpty());
    }

    @Test
    void testGetCurrentUser_Authenticated() {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
            .setEmail("current@example.com")
            .setPassword("password123")
            .setFullName("Current User")
            .build();

        AuthResponse registerResponse = blockingStub.register(registerRequest);
        String accessToken = registerResponse.getAccessToken();

        // For getCurrentUser, we need to attach the token as metadata
        // This requires creating a stub with credentials
        Metadata headers = new Metadata();
        headers.put(
            Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER),
            "Bearer " + accessToken
        );

        AuthServiceGrpc.AuthServiceBlockingStub authenticatedStub = blockingStub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers));

        GetCurrentUserRequest getCurrentUserRequest = GetCurrentUserRequest.newBuilder().build();
        GetCurrentUserResponse response = authenticatedStub.getCurrentUser(getCurrentUserRequest);
        
        assertNotNull(response);
        assertEquals("current@example.com", response.getUser().getEmail());
        assertEquals("Current User", response.getUser().getFullName());
    }
}
