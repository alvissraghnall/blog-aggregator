package com.ominimie.auth.config;

// import net.devh.boot.grpc.server.security.authentication.BearerAuthenticationReader;
// import net.devh.boot.grpc.server.security.authentication.GrpcAuthenticationReader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.security.GrpcAuthenticationExtractor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Configuration
public class SecurityConfig {

/*
    @Value("${spring.security.oauth2.resourceserver.jwt.key-value}")
    private String base64PublicKey;
*/

    @Bean
    public AuthenticationManager authenticationManager() {
        List<AuthenticationProvider> providers = new ArrayList<>();
        // providers.add(new JwtAuthenticationProvider(jwtDecoder()));
        return new ProviderManager(providers);
    }

    // @Bean
    // public GrpcAuthenticationExtractor authenticationReader() {
    //     return new BearerAuthenticationReader(BearerTokenAuthenticationToken::new);
    // }

/*
    @Bean
    public JwtDecoder jwtDecoder() {
        RSAPublicKey rsaPublicKey = parseRSAPublicKey(base64PublicKey);
        return NimbusJwtDecoder.withPublicKey(rsaPublicKey).build();
    }

    private RSAPublicKey parseRSAPublicKey(String base64Key) {
        try {
            byte[] decoded = Base64.getDecoder().decode(cleanKey(base64Key));
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid RSA public key", e);
        }
    }

    private String cleanKey(String key) {
        return key
                .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
    }
	*/
}
