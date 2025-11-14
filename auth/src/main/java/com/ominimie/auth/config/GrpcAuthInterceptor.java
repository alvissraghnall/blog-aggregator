 package com.ominimie.auth.config;

import java.util.UUID;

import org.springframework.security.oauth2.jwt.Jwt; 
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import com.ominimie.auth.user.domain.User;
import com.ominimie.auth.user.repos.UserRepository;

import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class GrpcAuthInterceptor implements ServerInterceptor { 
    private final JwtDecoder jwtDecoder;
    
    private final UserRepository userRepository;

    private static final Context.Key<User> USER_KEY = Context.key("user");
    private static final Metadata.Key<String> AUTH_HEADER = 
        Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call,
            Metadata headers,
            ServerCallHandler<ReqT, RespT> next) {

        String methodName = call.getMethodDescriptor().getFullMethodName();
        
        if (isPublicMethod(methodName)) {
            return next.startCall(call, headers);
        }

        String authHeader = headers.get(AUTH_HEADER);
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            call.close(Status.UNAUTHENTICATED.withDescription("Missing or invalid token"), headers);
            return new ServerCall.Listener<ReqT>() {};
        }

        String token = authHeader.substring(7);
        
        try {
            Jwt jwt = jwtDecoder.decode(token); 
            
            String userIdStr = jwt.getClaimAsString("user_id"); 
            if (userIdStr == null) {
                call.close(Status.UNAUTHENTICATED.withDescription("Invalid token claims"), headers);
                return new ServerCall.Listener<ReqT>() {};
            }

            UUID userId = UUID.fromString(userIdStr);
            User user = userRepository.findById(userId).orElse(null);

            if (user == null || !user.getActive()) {
                call.close(Status.PERMISSION_DENIED.withDescription("User not found or inactive"), headers);
                return new ServerCall.Listener<ReqT>() {};
            }

            Context context = Context.current().withValue(USER_KEY, user);
            return Contexts.interceptCall(context, call, headers, next);
            
        } catch (JwtException e) {
            call.close(Status.UNAUTHENTICATED.withDescription("Invalid JWT: " + e.getMessage()), headers);
            return new ServerCall.Listener<ReqT>() {};
        } catch (Exception e) {
            call.close(Status.INTERNAL.withDescription("Authentication error"), headers);
            return new ServerCall.Listener<ReqT>() {};
        }
    }

    private boolean isPublicMethod(String methodName) {
        return methodName.contains("Register") ||
               methodName.contains("Login") ||
               methodName.contains("InitiateOAuth") ||
               methodName.contains("CompleteOAuth") ||
               methodName.contains("RefreshToken") ||
               methodName.contains("ValidateToken");
    }

    public static User getCurrentUser() {
        return USER_KEY.get();
    }
}
