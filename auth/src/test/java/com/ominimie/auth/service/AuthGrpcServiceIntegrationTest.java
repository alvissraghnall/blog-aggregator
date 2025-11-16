package com.ominimie.auth.service;

import com.ominimie.auth.AbstractIntegrationTest;
import com.ominimie.auth.proto.*;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.MetadataUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class AuthGrpcServiceIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private AuthServiceGrpc.AuthServiceBlockingStub authStub;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void testRegisterAndLogin_Success() {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
                .setEmail("test.user@example.com")
                .setFullName("Test User")
                .setPassword("Password123!")
                .build();

        AuthResponse registerResponse = authStub.register(registerRequest);

        assertThat(registerResponse.getAccessToken()).isNotBlank();
        assertThat(registerResponse.getRefreshToken()).isNotBlank();
        assertThat(registerResponse.getUser().getEmail()).isEqualTo("test.user@example.com");
        assertThat(registerResponse.getUser().getFullName()).isEqualTo("Test User");
        assertThat(registerResponse.getExpiresIn()).isGreaterThan(0);

        var userOpt = userRepository.findByEmail("test.user@example.com");
        assertThat(userOpt).isPresent();
        var user = userOpt.get();
        assertThat(user.getFullName()).isEqualTo("Test User");
        assertThat(user.getActive()).isTrue();

        var providerOpt = authProviderRepository.findByUserAndProvider(user, ProviderType.LOCAL);
        assertThat(providerOpt).isPresent();
        assertThat(passwordEncoder.matches("Password123!", providerOpt.get().getPasswordHash())).isTrue();

        LoginRequest loginRequest = LoginRequest.newBuilder()
                .setEmail("test.user@example.com")
                .setPassword("Password123!")
                .build();

        AuthResponse loginResponse = authStub.login(loginRequest);
        assertThat(loginResponse.getAccessToken()).isNotBlank();
        assertThat(loginResponse.getUser().getId()).isEqualTo(user.getId().toString());
    }

    @Test
    void testRegister_EmailAlreadyExists() {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
                .setEmail("duplicate@example.com")
                .setFullName("Test User")
                .setPassword("Password123!")
                .build();
        
        authStub.register(registerRequest);
        
        assertThatThrownBy(() -> authStub.register(registerRequest))
                .isInstanceOf(StatusRuntimeException.class)
                .hasMessageContaining(Status.ALREADY_EXISTS.getCode().name())
                .hasMessageContaining("User with this email already exists");
    }

    @Test
    void testLogin_InvalidCredentials() {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
                .setEmail("login.fail@example.com")
                .setFullName("Test User")
                .setPassword("GoodPassword123!")
                .build();
        authStub.register(registerRequest);

        LoginRequest loginRequest = LoginRequest.newBuilder()
                .setEmail("login.fail@example.com")
                .setPassword("WrongPassword!")
                .build();

        assertThatThrownBy(() -> authStub.login(loginRequest))
                .isInstanceOf(StatusRuntimeException.class)
                .hasMessageContaining(Status.UNAUTHENTICATED.getCode().name())
                .hasMessageContaining("Invalid Credentials");
    }

    @Test
    void testRefreshToken_Success() {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
                .setEmail("refresh.user@example.com")
                .setFullName("Refresh User")
                .setPassword("Password123!")
                .build();
        AuthResponse registerResponse = authStub.register(registerRequest);
        String originalAccessToken = registerResponse.getAccessToken();
        String refreshToken = registerResponse.getRefreshToken();

        RefreshTokenRequest refreshRequest = RefreshTokenRequest.newBuilder()
                .setRefreshToken(refreshToken)
                .build();
        
        AuthResponse refreshResponse = authStub.refreshToken(refreshRequest);

        assertThat(refreshResponse.getAccessToken()).isNotBlank();
        assertThat(refreshResponse.getAccessToken()).isNotEqualTo(originalAccessToken);
        assertThat(refreshResponse.getRefreshToken()).isEqualTo(refreshToken);
        assertThat(refreshResponse.getUser().getEmail()).isEqualTo("refresh.user@example.com");
    }

    @Test
    void testValidateToken_SuccessAndFailure() {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
                .setEmail("validate.user@example.com")
                .setFullName("Validate User")
                .setPassword("Password123!")
                .build();
        AuthResponse registerResponse = authStub.register(registerRequest);
        String validToken = registerResponse.getAccessToken();

        ValidateTokenRequest validReq = ValidateTokenRequest.newBuilder().setToken(validToken).build();
        ValidateTokenResponse validResp = authStub.validateToken(validReq);
        
        assertThat(validResp.getValid()).isTrue();
        assertThat(validResp.getUser().getEmail()).isEqualTo("validate.user@example.com");
        assertThat(validResp.getError()).isEmpty();

        ValidateTokenRequest invalidReq = ValidateTokenRequest.newBuilder().setToken("bogus.token.value").build();
        ValidateTokenResponse invalidResp = authStub.validateToken(invalidReq);

        assertThat(invalidResp.getValid()).isFalse();
        assertThat(invalidResp.hasUser()).isFalse();
        assertThat(invalidResp.getError()).contains("Token is invalid or expired");
    }

    @Test
    void testGetCurrentUser_Authenticated() {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
                .setEmail("current.user@example.com")
                .setFullName("Current User")
                .setPassword("Password123!")
                .build();
        AuthResponse registerResponse = authStub.register(registerRequest);
        String token = registerResponse.getAccessToken();

		Metadata headers = new Metadata();
        headers.put(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer " + token);
        AuthServiceGrpc.AuthServiceBlockingStub authenticatedStub = authStub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers));

        // 3. Call protected endpoint
        GetCurrentUserRequest request = GetCurrentUserRequest.getDefaultInstance();
        GetCurrentUserResponse response = authenticatedStub.getCurrentUser(request);

        assertThat(response.getUser().getEmail()).isEqualTo("current.user@example.com");
        assertThat(response.getUser().getId()).isEqualTo(registerResponse.getUser().getId());
    }

    @Test
    void testGetCurrentUser_Unauthenticated() {
        // Call protected endpoint with unauthenticated stub
        GetCurrentUserRequest request = GetCurrentUserRequest.getDefaultInstance();

        assertThatThrownBy(() -> authStub.getCurrentUser(request))
                .isInstanceOf(StatusRuntimeException.class)
                .hasMessageContaining(Status.UNAUTHENTICATED.getCode().name());
                // .hasMessageContaining("Missing or invalid token");
    }

}
