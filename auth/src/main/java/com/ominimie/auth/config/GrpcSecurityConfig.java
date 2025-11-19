package com.ominimie.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.BearerTokenAuthenticationExtractor;
import org.springframework.grpc.server.security.GrpcAuthenticationExtractor;
import org.springframework.grpc.server.security.GrpcSecurity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;

import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@RequiredArgsConstructor
public class GrpcSecurityConfig {

    @Autowired
    private final AuthenticationManager authenticationManager;

    @Autowired
    private final UserDetailsService userDetailsService;

    private static final Metadata.Key<String> AUTHORIZATION_KEY = 
        Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER);

    @Bean
    @GlobalServerInterceptor
    public AuthenticationProcessInterceptor grpcSecurityFilterChain(
            GrpcSecurity grpc, 
            JwtDecoder jwtDecoder) throws Exception {
        return grpc
            .authorizeRequests(requests -> requests
                .methods("com.ominimie.auth.AuthService/Register").permitAll()
                .methods("com.ominimie.auth.AuthService/Login").permitAll()
                .methods("com.ominimie.auth.AuthService/RefreshToken").permitAll()
                .methods("com.ominimie.auth.AuthService/ValidateToken").permitAll()
                .methods("com.ominimie.auth.AuthService/VerifyEmail").permitAll()
                .methods("com.ominimie.auth.AuthService/InitiateOAuth").permitAll()
                .methods("com.ominimie.auth.AuthService/CompleteOAuth").permitAll()
                .methods("com.ominimie.auth.AuthService/GetCurrentUser").authenticated()
                .methods("com.ominimie.auth.AuthService/ResendVerificationEmail").authenticated()
                .methods("com.ominimie.auth.AuthService/LinkProvider").authenticated()
                .methods("com.ominimie.auth.AuthService/UnlinkProvider").authenticated()
                // Allow gRPC reflection and health checks
                .methods("grpc.*/*").permitAll()
                .allRequests().denyAll()
            )
            .authenticationManager(authenticationManager)
            .userDetailsService(userDetailsService)
            .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(withDefaults()))
            .authenticationExtractor(new BearerTokenAuthenticationExtractor())
            // .authenticationSchemeSelector(new BearerTokenAuthenticationReader(jwtDecoder))
            .build();
    }

    private static class BearerTokenAuthenticationReader {
        private final JwtDecoder jwtDecoder;

        BearerTokenAuthenticationReader(JwtDecoder jwtDecoder) {
            this.jwtDecoder = jwtDecoder;
        }

        public Authentication readAuthentication(ServerCall<?, ?> call, Metadata headers) {
            String authHeader = headers.get(AUTHORIZATION_KEY);
            
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return new UsernamePasswordAuthenticationToken(
                    "anonymous",
                    null,
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))
                );
            }

            String token = authHeader.substring(7);
            
            try {
                Jwt jwt = jwtDecoder.decode(token);
                return new UsernamePasswordAuthenticationToken(
                    jwt,
                    token,
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
                );
            } catch (Exception e) {
                return null;
            }
        }
    }
}


//     @Bean
//     public GrpcAuthenticationExtractor grpcAuthenticationReader() {
//         List<GrpcAuthenticationExtractor> readers = Arrays.asList(
//             new BearerTokenAuthenticationExtractor(),
//             new BasicGrp() 
//         );
//         return new CompositeGrpcAuthenticationReader(readers);
//     }
