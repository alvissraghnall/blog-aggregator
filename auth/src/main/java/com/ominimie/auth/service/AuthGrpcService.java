package com.ominimie.auth.service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.grpc.server.service.GrpcService;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.ominimie.auth.auth_provider.domain.AuthProvider;
import com.ominimie.auth.auth_provider.repos.AuthProviderRepository;
import com.ominimie.auth.config.GrpcAuthInterceptor;
import com.ominimie.auth.user.domain.User;
import com.ominimie.auth.user.repos.UserRepository;

import com.ominimie.auth.proto.RegisterRequest;
import com.ominimie.auth.proto.UserInfo;
import com.ominimie.auth.proto.ValidateTokenRequest;
import com.ominimie.auth.proto.ValidateTokenResponse;
import com.ominimie.auth.service.oauth2.OAuth2Service;
import com.ominimie.auth.service.oauth2.OAuth2TokenIntrospection;
import com.ominimie.auth.service.oauth2.OAuth2TokenResponse;
import com.ominimie.auth.service.oauth2.OAuth2TokenService;
import com.ominimie.auth.service.oauth2.OAuth2UserInfo;
import com.ominimie.auth.proto.AuthResponse;
import com.ominimie.auth.proto.AuthServiceGrpc;
import com.ominimie.auth.proto.CompleteOAuthRequest;
import com.ominimie.auth.proto.GetCurrentUserRequest;
import com.ominimie.auth.proto.GetCurrentUserResponse;
import com.ominimie.auth.proto.InitiateOAuthRequest;
import com.ominimie.auth.proto.InitiateOAuthResponse;
import com.ominimie.auth.proto.LoginRequest;
import com.ominimie.auth.proto.ProviderInfo;
import com.ominimie.auth.proto.ProviderType;
import com.ominimie.auth.proto.RefreshTokenRequest;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import lombok.RequiredArgsConstructor;

@GrpcService
@RequiredArgsConstructor
public class AuthGrpcService extends AuthServiceGrpc.AuthServiceImplBase {

    private final UserRepository userRepository;
    
    private final AuthProviderRepository authProviderRepository;
    
    private final PasswordEncoder passwordEncoder;
    
    private final JwtDecoder jwtDecoder;

    private final OAuth2TokenService oAuth2TokenService;

	private final OAuth2Service oAuth2Service;

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
            user = userRepository.save(user);

            AuthProvider authProvider = new AuthProvider();
            authProvider.setUser(user);
            authProvider.setProvider(ProviderType.LOCAL);
            authProvider.setPasswordHash(passwordEncoder.encode(request.getPassword()));
            authProvider.setProviderUserEmail(request.getEmail());
            authProviderRepository.save(authProvider);

            OAuth2TokenResponse tokenResponse = oAuth2TokenService.generateTokens(request.getEmail(), request.getPassword());

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
            User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> Status.UNAUTHENTICATED
                    .withDescription("Invalid credentials")
                    .asRuntimeException());

            if (!user.getActive()) {
                responseObserver.onError(Status.PERMISSION_DENIED
                    .withDescription("Account is inactive")
                    .asRuntimeException());
                return;
            }

            OAuth2TokenResponse oAuth2TokenResponse = oAuth2TokenService.generateTokens(request.getEmail(),
                request.getPassword());

            // AuthProvider localProvider = authProviderRepository
            //     .findByUserAndProvider(user, ProviderType.LOCAL)
            //     .orElseThrow(() -> Status.UNAUTHENTICATED
            //         .withDescription("Invalid credentials")
            //         .asRuntimeException());

            // if (!passwordEncoder.matches(request.getPassword(), localProvider.getPasswordHash())) {
            //     responseObserver.onError(Status.UNAUTHENTICATED
            //         .withDescription("Invalid credentials")
            //         .asRuntimeException());
            //     return;
            // }

            AuthResponse response = buildAuthResponse(user, oAuth2TokenResponse);
            
            responseObserver.onNext(response);
            responseObserver.onCompleted();
        } catch (StatusRuntimeException e) {
            responseObserver.onError(e);
        } catch (BadCredentialsException e) {
            responseObserver.onError(Status.UNAUTHENTICATED.withDescription("Invalid Credentials").asRuntimeException());
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
            OAuth2TokenResponse tokenResponse = oAuth2TokenService.refreshToken(
                request.getRefreshToken()
            );

            Jwt jwt = jwtDecoder.decode(tokenResponse.getAccessTokenValue());
            UUID userId = UUID.fromString(jwt.getClaimAsString("user_id"));
            
            User user = userRepository.findById(userId)
                .orElseThrow(() -> Status.NOT_FOUND
                    .withDescription("User not found")
                    .asRuntimeException());

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
            OAuth2TokenIntrospection introspection = oAuth2TokenService.introspectToken(
                request.getToken()
            );

            ValidateTokenResponse.Builder responseBuilder = ValidateTokenResponse.newBuilder()
                .setValid(introspection.isActive());

            if (introspection.isActive() && introspection.getUser() != null) {
                responseBuilder.setUser(buildUserInfo(introspection.getUser()));
            } else if (!introspection.isActive()) {
                responseBuilder.setError("Token is invalid or expired");
            }

            responseObserver.onNext(responseBuilder.build());
            responseObserver.onCompleted();
        } catch (Exception e) {
            responseObserver.onError(Status.INTERNAL
                .withDescription("Token validation failed: " + e.getMessage())
                .asRuntimeException());
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

	        OAuth2TokenResponse tokenResponse = oAuth2TokenService.generateTokensForOAuthUser(user);

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
	        
	        // Store state in cache or database for validation when callback is received
	        // cacheService.storeOAuthState(state, request.getProvider(), request.getRedirectUri());
	        
	        String authorizationUrl = oAuth2Service.buildAuthorizationUrl(
	            request.getProvider(), 
	            state, 
	            request.getRedirectUri()
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
    public void getCurrentUser(GetCurrentUserRequest request, 
                              StreamObserver<GetCurrentUserResponse> responseObserver) {
        try {
            User user = GrpcAuthInterceptor.getCurrentUser();
            
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

    private AuthResponse buildAuthResponse(User user, OAuth2TokenResponse tokenResponse) {
        long expiresIn = Duration.between(Instant.now(), tokenResponse.getAccessTokenExpiresAt())
            .getSeconds();

        return AuthResponse.newBuilder()
            .setAccessToken(tokenResponse.getAccessTokenValue())
            .setRefreshToken(tokenResponse.getRefreshTokenValue())
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
            .setActive(user.getActive());

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
