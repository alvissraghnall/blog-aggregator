package com.ominimie.auth.service;

import com.ominimie.auth.auth_provider.domain.AuthProvider;
import com.ominimie.auth.auth_provider.repos.AuthProviderRepository;
import com.ominimie.auth.email_verification.service.EmailVerificationService;
import com.ominimie.auth.proto.*;
import com.ominimie.auth.service.oauth2.OAuth2Service;
import com.ominimie.auth.service.oauth2.OAuth2UserInfo;
import com.ominimie.auth.user.domain.User;
import com.ominimie.auth.user.repos.UserRepository;
import com.ominimie.auth.user.service.CustomUserDetailsService;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.grpc.server.service.GrpcService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.UUID;

@GrpcService
@RequiredArgsConstructor
public class AuthGrpcService extends AuthServiceGrpc.AuthServiceImplBase {

    private final UserRepository userRepository;
    private final AuthProviderRepository authProviderRepository;
    private final PasswordEncoder passwordEncoder;
    private final CustomUserDetailsService userDetailsService;
    private final TokenService tokenService;
    private final OAuth2Service oAuth2Service;
    private final EmailVerificationService emailVerificationService;
    
    @Override
    public void register(RegisterRequest request, StreamObserver<AuthResponse> responseObserver) {
        try {
            if (userRepository.existsByEmailIgnoreCase(request.getEmail())) {
                responseObserver.onError(Status.ALREADY_EXISTS
                    .withDescription("User with this email already exists")
                    .asRuntimeException());
                return;
            }

            User user = new User();
            user.setEmail(request.getEmail());
            user.setFullName(request.getFullName());
            user.setActive(true);
            user.setEmailVerified(false);
            user = userRepository.save(user);

            AuthProvider authProvider = new AuthProvider();
            authProvider.setUser(user);
            authProvider.setProvider(ProviderType.LOCAL);
            authProvider.setPasswordHash(passwordEncoder.encode(request.getPassword()));
            authProvider.setProviderUserEmail(request.getEmail());
            authProviderRepository.save(authProvider);

            emailVerificationService.generateVerificationToken(user);

            TokenService.TokenResponse tokenResponse = tokenService.generateTokens(user);

            AuthResponse response = buildAuthResponse(user, tokenResponse);
            
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(Status.INTERNAL
                .withDescription("Registration failed: " + e.getMessage())
                .asRuntimeException());
        }
    }

    @Override
    public void login(LoginRequest request, StreamObserver<AuthResponse> responseObserver) {
        try {
            UserDetails userDetails;
            try {
                userDetails = userDetailsService.loadUserByUsername(request.getEmail());
            } catch (Exception e) {
                throw Status.UNAUTHENTICATED.withDescription("Invalid credentials").asRuntimeException();
            }

            if (!passwordEncoder.matches(request.getPassword(), userDetails.getPassword())) {
                throw Status.UNAUTHENTICATED.withDescription("Invalid credentials").asRuntimeException();
            }
            
            if (!userDetails.isEnabled()) {
                throw Status.PERMISSION_DENIED.withDescription("Account is inactive").asRuntimeException();
            }

            User user = userRepository.findByEmail(request.getEmail()).get();
            
            // Check if email is verified for local accounts
            if (!user.getEmailVerified() && authProviderRepository.existsByUserAndProvider(user, ProviderType.LOCAL)) {
                throw Status.PERMISSION_DENIED.withDescription("Email not verified").asRuntimeException();
            }

            TokenService.TokenResponse tokenResponse = tokenService.generateTokens(user);

            AuthResponse response = buildAuthResponse(user, tokenResponse);
            
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (StatusRuntimeException e) {
            responseObserver.onError(e);
        } catch (Exception e) {
            responseObserver.onError(Status.INTERNAL
                .withDescription("Login failed: " + e.getMessage())
                .asRuntimeException());
        }
    }
    
    @Override
    public void refreshToken(RefreshTokenRequest request, 
                            StreamObserver<AuthResponse> responseObserver) {
        try {
            TokenService.TokenResponse tokenResponse = tokenService.refreshToken(request.getRefreshToken());

            User user = tokenService.validateAccessToken(tokenResponse.getAccessToken());

            AuthResponse response = buildAuthResponse(user, tokenResponse);
            
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(Status.UNAUTHENTICATED
                .withDescription("Token refresh failed: " + e.getMessage())
                .asRuntimeException());
        }
    }

    @Override
    public void validateToken(ValidateTokenRequest request, 
                             StreamObserver<ValidateTokenResponse> responseObserver) {
        try {
            User user = tokenService.validateAccessToken(request.getToken());

            ValidateTokenResponse.Builder responseBuilder = ValidateTokenResponse.newBuilder()
                .setValid(true)
                .setUser(buildUserInfo(user));

            responseObserver.onNext(responseBuilder.build());
            responseObserver.onCompleted();
        } catch (Exception e) {
             ValidateTokenResponse response = ValidateTokenResponse.newBuilder()
                .setValid(false)
                .setError("Token is invalid or expired")
                .build();
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        }
    }

    @Override
    public void verifyEmail(VerifyEmailRequest request, 
                           StreamObserver<VerifyEmailResponse> responseObserver) {
        try {
            User user = emailVerificationService.verifyToken(request.getToken());
        
            VerifyEmailResponse response = VerifyEmailResponse.newBuilder()
                .setSuccess(true)
                .setMessage("Email verified successfully")
                .build();
            
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (StatusRuntimeException e) {
            responseObserver.onError(e);
        } catch (Exception e) {
            responseObserver.onError(Status.NOT_FOUND
                .withDescription("Invalid or expired verification token: " + e.getMessage())
                .asRuntimeException());
        }
    }

    @Override
    public void resendVerificationEmail(ResendVerificationEmailRequest request, 
                                       StreamObserver<ResendVerificationEmailResponse> responseObserver) {
        try {
            User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> Status.NOT_FOUND
                    .withDescription("User not found")
                    .asRuntimeException());
            
            if (user.getEmailVerified()) {
                throw Status.ALREADY_EXISTS
                    .withDescription("Email already verified")
                    .asRuntimeException();
            }

            emailVerificationService.deleteExistingTokensForUser(user);
            emailVerificationService.generateVerificationToken(user);
            
            ResendVerificationEmailResponse response = ResendVerificationEmailResponse.newBuilder()
                .setSuccess(true)
                .setMessage("Verification email sent")
                .build();
                
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception e) {
            ResendVerificationEmailResponse response = ResendVerificationEmailResponse.newBuilder()
                .setSuccess(false)
                .setMessage(e.getMessage())
                .build();
                
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        }
    }

    @Override
    public void completeOAuth(CompleteOAuthRequest request, 
                             StreamObserver<AuthResponse> responseObserver) {
        try {
            OAuth2UserInfo userInfo = oAuth2Service.exchangeCodeForUserInfo(
                request.getProvider(), 
                request.getCode()
            );

            User user = userRepository.findByEmail(userInfo.getEmail())
                .orElseGet(() -> createUserFromOAuth(userInfo));

            AuthProvider authProvider = authProviderRepository
                .findByUserAndProvider(user, request.getProvider())
                .orElseGet(() -> createAuthProvider(user, request.getProvider(), userInfo));

            if (!authProvider.getProviderUserId().equals(userInfo.getId())) {
                authProvider.setProviderUserId(userInfo.getId());
                authProvider.setProviderUserEmail(userInfo.getEmail());
                authProviderRepository.save(authProvider);
            }

            if (!user.getEmailVerified()) {
                user.setEmailVerified(true);
                userRepository.save(user);
            }

            TokenService.TokenResponse tokenResponse = tokenService.generateTokens(user);

            AuthResponse response = buildAuthResponse(user, tokenResponse);

            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(Status.INTERNAL
                .withDescription("OAuth completion failed: " + e.getMessage())
                .asRuntimeException());
        }
    }

    @Override
    public void initiateOAuth(InitiateOAuthRequest request, 
                             StreamObserver<InitiateOAuthResponse> responseObserver) {
        try {
            String state = UUID.randomUUID().toString();
            
            String authorizationUrl = oAuth2Service.buildAuthorizationUrl(
                request.getProvider(), 
                state, 
                request.getRedirectUri() // redirect_uri is for client
            );
            
            InitiateOAuthResponse response = InitiateOAuthResponse.newBuilder()
                .setAuthorizationUrl(authorizationUrl)
                .setState(state)
                .build();
                
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(Status.INTERNAL
                .withDescription("Failed to initiate OAuth: " + e.getMessage())
                .asRuntimeException());
        }
    }

    @Override
    public void linkProvider(LinkProviderRequest request, 
                            StreamObserver<LinkProviderResponse> responseObserver) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            Jwt jwt = (Jwt) auth.getPrincipal();
            UUID userId = UUID.fromString(jwt.getSubject()); 
            
            User user = userRepository.findById(userId)
                .orElseThrow(() -> Status.NOT_FOUND
                    .withDescription("User not found from token")
                    .asRuntimeException());
            
            if (authProviderRepository.existsByUserAndProvider(user, request.getProvider())) {
                throw Status.ALREADY_EXISTS
                    .withDescription("Provider already linked to this account")
                    .asRuntimeException();
            }
            
            OAuth2UserInfo userInfo = oAuth2Service.exchangeCodeForUserInfo(
                request.getProvider(), 
                request.getCode()
            );
            
            AuthProvider authProvider = createAuthProvider(user, request.getProvider(), userInfo);
            
            ProviderInfo providerInfo = ProviderInfo.newBuilder()
                .setProvider(authProvider.getProvider())
                .setProviderUserEmail(authProvider.getProviderUserEmail() != null ? 
                    authProvider.getProviderUserEmail() : "")
                .build();
            
            LinkProviderResponse response = LinkProviderResponse.newBuilder()
                .setSuccess(true)
                .setProviderInfo(providerInfo)
                .build();
                
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception e) {
            LinkProviderResponse response = LinkProviderResponse.newBuilder()
                .setSuccess(false)
                .setMessage(e.getMessage())
                .build();
                
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        }
    }

    @Override
    public void unlinkProvider(UnlinkProviderRequest request, 
                              StreamObserver<UnlinkProviderResponse> responseObserver) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            Jwt jwt = (Jwt) auth.getPrincipal();
            UUID userId = UUID.fromString(jwt.getSubject()); 
            
            User user = userRepository.findById(userId)
                .orElseThrow(() -> Status.NOT_FOUND
                    .withDescription("User not found from token")
                    .asRuntimeException());
            
            AuthProvider authProvider = authProviderRepository.findByUserAndProvider(user, request.getProvider())
                .orElseThrow(() -> Status.NOT_FOUND
                    .withDescription("Provider not linked to this account")
                    .asRuntimeException());
            
            // refute unlinking if it's the only auth provider
            if (authProviderRepository.findByUser(user).size() <= 1) {
                throw Status.FAILED_PRECONDITION
                    .withDescription("Cannot unlink the only authentication method")
                    .asRuntimeException();
            }
            
            authProviderRepository.delete(authProvider);
            
            UnlinkProviderResponse response = UnlinkProviderResponse.newBuilder()
                .setSuccess(true)
                .build();
                
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception e) {
            UnlinkProviderResponse response = UnlinkProviderResponse.newBuilder()
                .setSuccess(false)
                .setMessage(e.getMessage())
                .build();
                
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        }
    }

    @Override
    public void getCurrentUser(GetCurrentUserRequest request, 
                              StreamObserver<GetCurrentUserResponse> responseObserver) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            Jwt jwt = (Jwt) auth.getPrincipal();
            UUID userId = UUID.fromString(jwt.getSubject()); 
            
            User user = userRepository.findById(userId)
                .orElseThrow(() -> Status.NOT_FOUND
                    .withDescription("User not found from token")
                    .asRuntimeException());
            
            GetCurrentUserResponse response = GetCurrentUserResponse.newBuilder()
                .setUser(buildUserInfo(user))
                .build();
            
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(Status.UNAUTHENTICATED
                .withDescription("Not authenticated")
                .asRuntimeException());
        }
    }

    private AuthResponse buildAuthResponse(User user, TokenService.TokenResponse tokenResponse) {
        long expiresIn = Duration.between(Instant.now(), tokenResponse.getAccessTokenExpiresAt())
            .getSeconds();

        return AuthResponse.newBuilder()
            .setAccessToken(tokenResponse.getAccessToken())
            .setRefreshToken(tokenResponse.getRefreshToken())
            .setUser(buildUserInfo(user))
            .setExpiresIn(expiresIn)
            .build();
    }

    private UserInfo buildUserInfo(User user) {
        List<AuthProvider> providers = authProviderRepository.findByUser(user);
        
        UserInfo.Builder builder = UserInfo.newBuilder()
            .setId(user.getId().toString())
            .setEmail(user.getEmail())
            .setFullName(user.getFullName())
            .setActive(user.getActive())
            .setEmailVerified(user.getEmailVerified());

        for (AuthProvider provider : providers) {
            if (provider.getProvider() != ProviderType.LOCAL) {
                builder.addProviders(ProviderInfo.newBuilder()
                    .setProvider(provider.getProvider())
                    .setProviderUserEmail(provider.getProviderUserEmail() != null ? 
                        provider.getProviderUserEmail() : "")
                    .build());
            }
        }
        return builder.build();
    }

    private User createUserFromOAuth(OAuth2UserInfo userInfo) {
        User user = new User();
        user.setEmail(userInfo.getEmail());
        user.setFullName(userInfo.getName());
        user.setActive(true);
        user.setEmailVerified(true);
        return userRepository.save(user);
    }

    private AuthProvider createAuthProvider(User user, ProviderType providerType, 
                                           OAuth2UserInfo userInfo) {
        AuthProvider authProvider = new AuthProvider();
        authProvider.setUser(user);
        authProvider.setProvider(providerType);
        authProvider.setProviderUserId(userInfo.getId());
        authProvider.setProviderUserEmail(userInfo.getEmail());
        return authProviderRepository.save(authProvider);
    }
}
