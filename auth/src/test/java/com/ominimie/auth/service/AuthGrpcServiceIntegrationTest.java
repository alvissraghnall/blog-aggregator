package com.ominimie.auth.service;

import com.ominimie.auth.AbstractIntegrationTest;
import com.ominimie.auth.proto.*;
import com.ominimie.auth.user.domain.User;
import com.ominimie.auth.auth_provider.domain.AuthProvider;
import com.ominimie.auth.config.TestMailConfig;
import com.ominimie.auth.email_verification.domain.EmailVerificationToken;
import com.ominimie.auth.proto.ProviderType;
import com.ominimie.auth.service.oauth2.GithubOAuth2UserInfo;
import com.ominimie.auth.service.oauth2.GoogleOAuth2UserInfo;
import com.ominimie.auth.service.oauth2.OAuth2Service;
import com.ominimie.auth.service.oauth2.OAuth2TestConfig;
import com.ominimie.auth.service.oauth2.OAuth2UserInfo;

import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.MetadataUtils;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static com.icegreen.greenmail.util.GreenMailUtil.getBody;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Import({ OAuth2TestConfig.class, TestMailConfig.class })
public class AuthGrpcServiceIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    private AuthServiceGrpc.AuthServiceBlockingStub authStub;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private OAuth2Service oAuth2Service;

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
        assertThat(registerResponse.getUser().getEmailVerified()).isFalse(); 
        assertThat(registerResponse.getExpiresIn()).isGreaterThan(0);

        var userOpt = userRepository.findByEmail("test.user@example.com");
        assertThat(userOpt).isPresent();
        var user = userOpt.get();
        assertThat(user.getFullName()).isEqualTo("Test User");
        assertThat(user.getActive()).isTrue();
        assertThat(user.getEmailVerified()).isFalse();

        var providerOpt = authProviderRepository.findByUserAndProvider(user, ProviderType.LOCAL);
        assertThat(providerOpt).isPresent();
        assertThat(passwordEncoder.matches("Password123!", providerOpt.get().getPasswordHash())).isTrue();

        LoginRequest loginRequest = LoginRequest.newBuilder()
                .setEmail("test.user@example.com")
                .setPassword("Password123!")
                .build();

        assertThatThrownBy(() -> authStub.login(loginRequest))
                .isInstanceOf(StatusRuntimeException.class)
                .hasMessageContaining(Status.PERMISSION_DENIED.getCode().name())
                .hasMessageContaining("Email not verified");

        var emailTokenOpt = emailVerificationTokenRepository.findByUser(user);
        assertThat(emailTokenOpt).isPresent();
        String emailToken = emailTokenOpt.get().getId();

        VerifyEmailRequest verifyRequest = VerifyEmailRequest.newBuilder()
                .setToken(emailToken)
                .build();

        VerifyEmailResponse verifyResponse = authStub.verifyEmail(verifyRequest);
        assertThat(verifyResponse.getSuccess()).isTrue();

        user = userRepository.findById(user.getId()).get();
        assertThat(user.getEmailVerified()).isTrue();

        AuthResponse loginResponse = authStub.login(loginRequest);
        assertThat(loginResponse.getAccessToken()).isNotBlank();
        assertThat(loginResponse.getUser().getId()).isEqualTo(user.getId().toString());
        assertThat(loginResponse.getUser().getEmailVerified()).isTrue();
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

        var userOpt = userRepository.findByEmail("login.fail@example.com");
        var emailTokenOpt = emailVerificationTokenRepository.findByUser(userOpt.get());
        VerifyEmailRequest verifyRequest = VerifyEmailRequest.newBuilder()
                .setToken(emailTokenOpt.get().getId())
                .build();
        authStub.verifyEmail(verifyRequest);

        LoginRequest loginRequest = LoginRequest.newBuilder()
                .setEmail("login.fail@example.com")
                .setPassword("WrongPassword!")
                .build();

        assertThatThrownBy(() -> authStub.login(loginRequest))
                .isInstanceOf(StatusRuntimeException.class)
                .hasMessageContaining(Status.UNAUTHENTICATED.getCode().name())
                .hasMessageContaining("Invalid credentials");
    }

    // @Test
    // void testRefreshToken_Success() {
    //     RegisterRequest registerRequest = RegisterRequest.newBuilder()
    //             .setEmail("refresh.user@example.com")
    //             .setFullName("Refresh User")
    //             .setPassword("Password123!")
    //             .build();
    //     AuthResponse registerResponse = authStub.register(registerRequest);

    //     var userOpt = userRepository.findByEmail("refresh.user@example.com");
    //     var emailTokenOpt = emailVerificationTokenRepository.findByUser(userOpt.get());
    //     VerifyEmailRequest verifyRequest = VerifyEmailRequest.newBuilder()
    //             .setToken(emailTokenOpt.get().getId())
    //             .build();
    //     authStub.verifyEmail(verifyRequest);

    //     String originalAccessToken = registerResponse.getAccessToken();
    //     String refreshToken = registerResponse.getRefreshToken();

    //     RefreshTokenRequest refreshRequest = RefreshTokenRequest.newBuilder()
    //             .setRefreshToken(refreshToken)
    //             .build();

    //     AuthResponse refreshResponse = authStub.refreshToken(refreshRequest);

    //     assertThat(refreshResponse.getAccessToken()).isNotBlank();
    //     assertThat(refreshResponse.getAccessToken()).isNotEqualTo(originalAccessToken);

    //     assertThat(refreshResponse.getRefreshToken()).isNotEqualTo(refreshToken);
    //     assertThat(refreshResponse.getUser().getEmail()).isEqualTo("refresh.user@example.com");
    // }

    @Test
    void testRefreshToken_Success() throws InterruptedException {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
                .setEmail("refresh.user@example.com")
                .setFullName("Refresh User")
                .setPassword("Password123!")
                .build();
        AuthResponse registerResponse = authStub.register(registerRequest);

        var userOpt = userRepository.findByEmail("refresh.user@example.com");
        var emailTokenOpt = emailVerificationTokenRepository.findByUser(userOpt.get());
        VerifyEmailRequest verifyRequest = VerifyEmailRequest.newBuilder()
                .setToken(emailTokenOpt.get().getId())
                .build();
        authStub.verifyEmail(verifyRequest);

        String originalAccessToken = registerResponse.getAccessToken();
        String refreshToken = registerResponse.getRefreshToken();

        // Sleep to ensure different timestamps (JWTs have second precision)
        Thread.sleep(1000);

        RefreshTokenRequest refreshRequest = RefreshTokenRequest.newBuilder()
                .setRefreshToken(refreshToken)
                .build();

        AuthResponse refreshResponse = authStub.refreshToken(refreshRequest);

        assertThat(refreshResponse.getAccessToken()).isNotBlank();
        assertThat(refreshResponse.getAccessToken()).isNotEqualTo(originalAccessToken);
    
        Jwt originalJwt = jwtDecoder.decode(originalAccessToken);
        Jwt refreshedJwt = jwtDecoder.decode(refreshResponse.getAccessToken());
    
        assertThat(refreshedJwt.getIssuedAt()).isAfter(originalJwt.getIssuedAt());
    
        assertThat(refreshResponse.getRefreshToken()).isNotBlank();
        assertThat(refreshResponse.getRefreshToken()).isNotEqualTo(refreshToken);
    
        assertThat(refreshResponse.getUser().getEmail()).isEqualTo("refresh.user@example.com");
    
        // Verify old refresh token is revoked (fails if reused)
        RefreshTokenRequest reuseRequest = RefreshTokenRequest.newBuilder()
                .setRefreshToken(refreshToken)
                .build();
    
        assertThatThrownBy(() -> authStub.refreshToken(reuseRequest))
                .isInstanceOf(StatusRuntimeException.class)
                .hasMessageContaining(Status.UNAUTHENTICATED.getCode().name());
    }

    @Test
    void testEmailVerification() {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
                .setEmail("verify.test@example.com")
                .setFullName("Verify Test")
                .setPassword("Password123!")
                .build();
        authStub.register(registerRequest);

        var userOpt = userRepository.findByEmail("verify.test@example.com");
        assertThat(userOpt).isPresent();
        User user = userOpt.get();
        assertThat(user.getEmailVerified()).isFalse();

        var emailTokenOpt = emailVerificationTokenRepository.findByUser(user);
        assertThat(emailTokenOpt).isPresent();
        String emailToken = emailTokenOpt.get().getId();

        VerifyEmailRequest verifyRequest = VerifyEmailRequest.newBuilder()
                .setToken(emailToken)
                .build();

        VerifyEmailResponse verifyResponse = authStub.verifyEmail(verifyRequest);
        assertThat(verifyResponse.getSuccess()).isTrue();

        user = userRepository.findById(user.getId()).get();
        assertThat(user.getEmailVerified()).isTrue();

        // Attempting to verify with the same token should throw NOT_FOUND
        assertThatThrownBy(() -> authStub.verifyEmail(verifyRequest))
                .isInstanceOf(StatusRuntimeException.class)
                .satisfies(exception -> {
                    StatusRuntimeException sre = (StatusRuntimeException) exception;
                    assertThat(sre.getStatus().getCode()).isEqualTo(Status.NOT_FOUND.getCode());
                    assertThat(sre.getStatus().getDescription())
                            .contains("Invalid or expired verification token");
                });
    }

    @Test
    void testEmailVerification_ExpiredToken() throws InterruptedException {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
                .setEmail("expired.test@example.com")
                .setFullName("Expired Test")
                .setPassword("Password123!")
                .build();
        authStub.register(registerRequest);

        var userOpt = userRepository.findByEmail("expired.test@example.com");
        User user = userOpt.get();
    
        var emailTokenOpt = emailVerificationTokenRepository.findByUser(user);
        EmailVerificationToken token = emailTokenOpt.get();
    
        // Manually expire the token
        token.setExpiresAt(Instant.now().minus(1, ChronoUnit.HOURS));
        emailVerificationTokenRepository.save(token);

        VerifyEmailRequest verifyRequest = VerifyEmailRequest.newBuilder()
                .setToken(token.getId())
                .build();

        assertThatThrownBy(() -> authStub.verifyEmail(verifyRequest))
                .isInstanceOf(StatusRuntimeException.class)
                .satisfies(exception -> {
                    StatusRuntimeException sre = (StatusRuntimeException) exception;
                    assertThat(sre.getStatus().getDescription())
                            .containsIgnoringCase("expired");
                });
    
    }

    @Test
    void testValidateToken_SuccessAndFailure() {
        RegisterRequest registerRequest = RegisterRequest.newBuilder()
                .setEmail("validate.user@example.com")
                .setFullName("Validate User")
                .setPassword("Password123!")
                .build();
        AuthResponse registerResponse = authStub.register(registerRequest);

        var userOpt = userRepository.findByEmail("validate.user@example.com");
        var emailTokenOpt = emailVerificationTokenRepository.findByUser(userOpt.get());
        VerifyEmailRequest verifyRequest = VerifyEmailRequest.newBuilder()
                .setToken(emailTokenOpt.get().getId())
                .build();
        authStub.verifyEmail(verifyRequest);

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

        var userOpt = userRepository.findByEmail("current.user@example.com");
        var emailTokenOpt = emailVerificationTokenRepository.findByUser(userOpt.get());
        VerifyEmailRequest verifyRequest = VerifyEmailRequest.newBuilder()
                .setToken(emailTokenOpt.get().getId())
                .build();
        authStub.verifyEmail(verifyRequest);

        String token = registerResponse.getAccessToken();

        Metadata headers = new Metadata();
        headers.put(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer " + token);
        AuthServiceGrpc.AuthServiceBlockingStub authenticatedStub = authStub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers));

        GetCurrentUserRequest request = GetCurrentUserRequest.getDefaultInstance();
        GetCurrentUserResponse response = authenticatedStub.getCurrentUser(request);

        assertThat(response.getUser().getEmail()).isEqualTo("current.user@example.com");
        assertThat(response.getUser().getId()).isEqualTo(registerResponse.getUser().getId());
        assertThat(response.getUser().getEmailVerified()).isTrue();
    }

    @Test
    void testGetCurrentUser_Unauthenticated() {

        GetCurrentUserRequest request = GetCurrentUserRequest.getDefaultInstance();

        assertThatThrownBy(() -> authStub.getCurrentUser(request))
                .isInstanceOf(StatusRuntimeException.class)
                .hasMessageContaining(Status.UNAUTHENTICATED.getCode().name());
    }

    // @Test
    // void testEmailVerification() {

    //     RegisterRequest registerRequest = RegisterRequest.newBuilder()
    //             .setEmail("verify.test@example.com")
    //             .setFullName("Verify Test")
    //             .setPassword("Password123!")
    //             .build();
    //     authStub.register(registerRequest);

    //     var userOpt = userRepository.findByEmail("verify.test@example.com");
    //     assertThat(userOpt).isPresent();
    //     User user = userOpt.get();
    //     assertThat(user.getEmailVerified()).isFalse();

    //     var emailTokenOpt = emailVerificationTokenRepository.findByUser(user);
    //     assertThat(emailTokenOpt).isPresent();
    //     String emailToken = emailTokenOpt.get().getId();

    //     VerifyEmailRequest verifyRequest = VerifyEmailRequest.newBuilder()
    //             .setToken(emailToken)
    //             .build();

    //     VerifyEmailResponse verifyResponse = authStub.verifyEmail(verifyRequest);
    //     assertThat(verifyResponse.getSuccess()).isTrue();

    //     user = userRepository.findById(user.getId()).get();
    //     assertThat(user.getEmailVerified()).isTrue();

    //     assertThatThrownBy(() -> authStub.verifyEmail(verifyRequest))
    //             .isInstanceOf(StatusRuntimeException.class)
    //             .hasMessageContaining(Status.NOT_FOUND.getCode().name());
    // }

    @Test
    void testResendVerificationEmail() {

        RegisterRequest registerRequest = RegisterRequest.newBuilder()
                .setEmail("resend.test@example.com")
                .setFullName("Resend Test")
                .setPassword("Password123!")
                .build();
        var registerResponse = authStub.register(registerRequest);

        ResendVerificationEmailRequest resendRequest = ResendVerificationEmailRequest.newBuilder()
                .setEmail("resend.test@example.com")
                .build();

        String token = registerResponse.getAccessToken();

        Metadata headers = new Metadata();
        headers.put(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer " + token);
        AuthServiceGrpc.AuthServiceBlockingStub authenticatedStub = authStub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers));

        ResendVerificationEmailResponse resendResponse = authenticatedStub.resendVerificationEmail(resendRequest);
        assertThat(resendResponse.getSuccess()).isTrue();

        var userOpt = userRepository.findByEmail("resend.test@example.com");
        var emailTokenOpt = emailVerificationTokenRepository.findByUser(userOpt.get());
        VerifyEmailRequest verifyRequest = VerifyEmailRequest.newBuilder()
                .setToken(emailTokenOpt.get().getId())
                .build();
        authenticatedStub.verifyEmail(verifyRequest);

        resendResponse = authenticatedStub.resendVerificationEmail(resendRequest);
        assertThat(resendResponse.getSuccess()).isFalse();
        assertThat(resendResponse.getMessage()).contains("already verified");
    }

    @Test
    void testOAuthFlow() {

        Map<String, Object> attrs = new HashMap<>();

        attrs.put("sub", "google_user_001");
        attrs.put("name", "Haha User");
        attrs.put("email", "google@google.io");

        OAuth2UserInfo mockUserInfo = new GoogleOAuth2UserInfo(attrs);

        when(oAuth2Service.exchangeCodeForUserInfo(
            eq(ProviderType.GOOGLE), 
            eq("mock_auth_code")
        )).thenReturn(mockUserInfo);

        InitiateOAuthRequest initiateRequest = InitiateOAuthRequest.newBuilder()
            .setProvider(ProviderType.GOOGLE)
            .setRedirectUri("http://localhost:3000/callback")
            .build();

        InitiateOAuthResponse initiateResponse = authStub.initiateOAuth(initiateRequest);

        assertThat(initiateResponse.getAuthorizationUrl()).isNotBlank();
        assertThat(initiateResponse.getState()).isNotBlank();

        CompleteOAuthRequest completeRequest = CompleteOAuthRequest.newBuilder()
            .setProvider(ProviderType.GOOGLE)
            .setCode("mock_auth_code")
            .setState(initiateResponse.getState())
            .build();

        AuthResponse authResponse = authStub.completeOAuth(completeRequest);

        assertThat(authResponse.getAccessToken()).isNotBlank();
        assertThat(authResponse.getRefreshToken()).isNotBlank();
        assertThat(authResponse.getUser().getEmail()).isEqualTo("google@google.io");
        assertThat(authResponse.getUser().getFullName()).isEqualTo("Haha User");
        assertThat(authResponse.getUser().getEmailVerified()).isTrue(); 

        verify(oAuth2Service).exchangeCodeForUserInfo(ProviderType.GOOGLE, "mock_auth_code");
    }
    
    @Test
    void testLinkAndUnlinkProvider() {

        RegisterRequest registerRequest = RegisterRequest.newBuilder()
            .setEmail("link.test@example.com")
            .setFullName("Link Test")
            .setPassword("Password123!")
            .build();
        AuthResponse registerResponse = authStub.register(registerRequest);

        var userOpt = userRepository.findByEmail("link.test@example.com");
        var emailTokenOpt = emailVerificationTokenRepository.findByUser(userOpt.get());
        VerifyEmailRequest verifyRequest = VerifyEmailRequest.newBuilder()
            .setToken(emailTokenOpt.get().getId())
            .build();
        authStub.verifyEmail(verifyRequest);

        String token = registerResponse.getAccessToken();

        Metadata headers = new Metadata();
        headers.put(Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer " + token);
        AuthServiceGrpc.AuthServiceBlockingStub authenticatedStub = authStub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(headers));

        Map<String, Object> attrs = new HashMap<>();

        attrs.put("id", "github_user_456");
        attrs.put("name", "GH User");
        attrs.put("email", "user@github.io");
        
        OAuth2UserInfo mockUserInfo = new GithubOAuth2UserInfo(attrs);

        when(oAuth2Service.exchangeCodeForUserInfo(
            eq(ProviderType.GITHUB), 
            eq("mock_auth_code")
        )).thenReturn(mockUserInfo);

        LinkProviderRequest linkRequest = LinkProviderRequest.newBuilder()
            .setProvider(ProviderType.GITHUB)
            .setCode("mock_auth_code")
            .setState(UUID.randomUUID().toString())
            .build();

        LinkProviderResponse linkResponse = authenticatedStub.linkProvider(linkRequest);
        assertThat(linkResponse.getSuccess()).isTrue();

        User user = userOpt.get();
        var linkedProvider = authProviderRepository.findByUserAndProvider(user, ProviderType.GITHUB);
        assertThat(linkedProvider).isPresent();
        assertThat(linkedProvider.get().getProviderUserId()).isEqualTo("github_user_456");

        UnlinkProviderRequest unlinkRequest = UnlinkProviderRequest.newBuilder()
            .setProvider(ProviderType.GITHUB)
            .build();

        UnlinkProviderResponse unlinkResponse = authenticatedStub.unlinkProvider(unlinkRequest);
        assertThat(unlinkResponse.getSuccess()).isTrue();

        assertThat(authProviderRepository.findByUserAndProvider(user, ProviderType.GITHUB)).isEmpty();
    }

    @Test
    void testCompleteOAuth_NewUser() {
        Map<String, Object> attrs = new HashMap<>();

        attrs.put("sub", "google_user_007");
        attrs.put("name", "Flo Wirtz");
        attrs.put("email", "007@google.io");

        OAuth2UserInfo mockUserInfo = new GoogleOAuth2UserInfo(attrs);

        when(oAuth2Service.exchangeCodeForUserInfo(
        eq(ProviderType.GOOGLE), 
        eq("new_user_code")
        )).thenReturn(mockUserInfo);

        CompleteOAuthRequest completeRequest = CompleteOAuthRequest.newBuilder()
            .setProvider(ProviderType.GOOGLE)
            .setCode("new_user_code")
            .setState("some_state")
            .build();

        AuthResponse authResponse = authStub.completeOAuth(completeRequest);

        assertThat(authResponse.getAccessToken()).isNotBlank();
        assertThat(authResponse.getUser().getEmail()).isEqualTo("007@google.io");
        assertThat(authResponse.getUser().getFullName()).isEqualTo("Flo Wirtz");
        assertThat(authResponse.getUser().getEmailVerified()).isTrue();

        var createdUser = userRepository.findByEmail("007@google.io");
        assertThat(createdUser).isPresent();
        assertThat(createdUser.get().getEmailVerified()).isTrue();
    }

    @Test
    void testCompleteOAuth_ExistingUser() {

            RegisterRequest registerRequest = RegisterRequest.newBuilder()
                    .setEmail("existing.oauth@example.com")
                    .setFullName("Existing User")
                    .setPassword("Password123!")
                    .build();
            authStub.register(registerRequest);

            var existingUser = userRepository.findByEmail("existing.oauth@example.com").get();
            var emailToken = emailVerificationTokenRepository.findByUser(existingUser).get();
            authStub.verifyEmail(VerifyEmailRequest.newBuilder().setToken(emailToken.getId()).build());

            Map<String, Object> attrs = new HashMap<>();

            attrs.put("sub", "existing_oauth_user_id");
            attrs.put("name", "Existing User");
            attrs.put("email", "existing.oauth@example.com");

            OAuth2UserInfo mockUserInfo = new GoogleOAuth2UserInfo(attrs);

            when(oAuth2Service.exchangeCodeForUserInfo(
                eq(ProviderType.GOOGLE), 
                eq("existing_user_code")
            )).thenReturn(mockUserInfo);

            CompleteOAuthRequest completeRequest = CompleteOAuthRequest.newBuilder()
                    .setProvider(ProviderType.GOOGLE)
                    .setCode("existing_user_code")
                    .setState("some_state")
                    .build();

            AuthResponse authResponse = authStub.completeOAuth(completeRequest);

            assertThat(authResponse.getAccessToken()).isNotBlank();
            assertThat(authResponse.getUser().getEmail()).isEqualTo("existing.oauth@example.com");
            assertThat(authResponse.getUser().getId()).isEqualTo(existingUser.getId().toString());

            var linkedProvider = authProviderRepository.findByUserAndProvider(existingUser, ProviderType.GOOGLE);
            assertThat(linkedProvider).isPresent();
            assertThat(linkedProvider.get().getProviderUserId()).isEqualTo("existing_oauth_user_id");
    }

    @Test
    void testEmailSending() {

        RegisterRequest registerRequest = RegisterRequest.newBuilder()
                .setEmail("email.test@example.com")
                .setFullName("Email Test")
                .setPassword("Password123!")
                .build();
        authStub.register(registerRequest);

        await().atMost(2, SECONDS).untilAsserted(() -> {
            MimeMessage[] receivedMessages = greenMail.getReceivedMessages();
            assertEquals(1, receivedMessages.length);

            MimeMessage receivedMessage = receivedMessages[0];
            assertThat(getBody(receivedMessage)).contains("verify");
            assertEquals(1, receivedMessage.getAllRecipients().length);
            assertEquals("email.test@example.com", receivedMessage.getAllRecipients()[0].toString());
        });
    }
}
