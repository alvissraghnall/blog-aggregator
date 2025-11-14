package com.ominimie.auth.oauth2_registered_client.repos;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import com.ominimie.auth.oauth2_registered_client.domain.Oauth2RegisteredClient;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class MongoRegisteredClientRepository implements RegisteredClientRepository {
    
    private final Oauth2RegisteredClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void save(RegisteredClient registeredClient) {
        Oauth2RegisteredClient entity = clientRepository.findByClientId(registeredClient.getClientId())
                .orElseGet(Oauth2RegisteredClient::new);

        mapToEntity(entity, registeredClient);

        clientRepository.save(entity);
    }

    @Override
    public RegisteredClient findById(String id) {
        return clientRepository.findById(Long.valueOf(id))
                .map(this::mapToRegisteredClient)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId)
                .map(this::mapToRegisteredClient)
                .orElse(null);
    }

    private void mapToEntity(Oauth2RegisteredClient entity, RegisteredClient registeredClient) {
        if (entity.getId() == null) {
            entity.setClientId(registeredClient.getClientId());
            // entity.setDateCreated(OffsetDateTime.now()); 
        }

        entity.setLastUpdated(OffsetDateTime.now());
        
        if (registeredClient.getClientSecret() != null) {
            String incomingSecret = registeredClient.getClientSecret();
            if (entity.getClientSecret() == null || !passwordEncoder.matches(incomingSecret, entity.getClientSecret())) {
                if (!isEncoded(incomingSecret)) {
                    entity.setClientSecret(passwordEncoder.encode(incomingSecret));
                } else {
                    entity.setClientSecret(incomingSecret);
                }
            }
        }

        entity.setClientAuthenticationMethods(registeredClient.getClientAuthenticationMethods().stream()
                .map(ClientAuthenticationMethod::getValue)
                .collect(Collectors.toSet()));
        entity.setAuthorizationGrantTypes(registeredClient.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue)
                .collect(Collectors.toSet()));
        entity.setRedirectUris(registeredClient.getRedirectUris());
        entity.setScopes(registeredClient.getScopes());

        entity.setClientSettings(registeredClient.getClientSettings().getSettings());
        entity.setTokenSettings(registeredClient.getTokenSettings().getSettings());
    }
    
    private boolean isEncoded(String secret) {
        return secret != null && secret.startsWith("{") && secret.contains("}");
    }

    private RegisteredClient mapToRegisteredClient(Oauth2RegisteredClient entity) {
        RegisteredClient.Builder builder = RegisteredClient.withId(entity.getId().toString())
            .clientId(entity.getClientId())
            .clientSecret(entity.getClientSecret())
            .clientAuthenticationMethods(authenticationMethods -> 
                entity.getClientAuthenticationMethods().forEach(method -> 
                    authenticationMethods.add(resolveClientAuthenticationMethod(method))))
            .authorizationGrantTypes(grantTypes -> 
                entity.getAuthorizationGrantTypes().forEach(grantType -> 
                    grantTypes.add(resolveAuthorizationGrantType(grantType))))
            .redirectUris(uris -> 
                entity.getRedirectUris().forEach(uri -> uris.add(uri)))
            .scopes(scopes -> 
                entity.getScopes().forEach(scope -> scopes.add(scope)));

        builder.clientSettings(ClientSettings.withSettings(entity.getClientSettings()).build());
        builder.tokenSettings(TokenSettings.withSettings(entity.getTokenSettings()).build());

        return builder.build();
    }

    private ClientAuthenticationMethod resolveClientAuthenticationMethod(String method) {
        return switch (method) {
            case "client_secret_basic" -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
            case "client_secret_post" -> ClientAuthenticationMethod.CLIENT_SECRET_POST;
            case "client_secret_jwt" -> ClientAuthenticationMethod.CLIENT_SECRET_JWT;
            case "private_key_jwt" -> ClientAuthenticationMethod.PRIVATE_KEY_JWT;
            case "none" -> ClientAuthenticationMethod.NONE;
            default -> new ClientAuthenticationMethod(method);
        };
    }

    private AuthorizationGrantType resolveAuthorizationGrantType(String grantType) {
        return switch (grantType) {
            case "authorization_code" -> AuthorizationGrantType.AUTHORIZATION_CODE;
            case "client_credentials" -> AuthorizationGrantType.CLIENT_CREDENTIALS;
            case "refresh_token" -> AuthorizationGrantType.REFRESH_TOKEN;
            case "password" -> AuthorizationGrantType.PASSWORD;
            case "urn:ietf:params:oauth:grant-type:device_code" -> AuthorizationGrantType.DEVICE_CODE;
            case "urn:ietf:params:oauth:grant-type:jwt-bearer" -> AuthorizationGrantType.JWT_BEARER;
            default -> new AuthorizationGrantType(grantType);
        };
    }
}
