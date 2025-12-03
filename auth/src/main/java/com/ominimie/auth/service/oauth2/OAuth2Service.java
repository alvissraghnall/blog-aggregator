package com.ominimie.auth.service.oauth2;

import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.ominimie.auth.proto.ProviderType;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class OAuth2Service {

    private final ClientRegistrationRepository clientRegistrationRepository;
    
    private final RestTemplate restTemplate;

    public String buildAuthorizationUrl(ProviderType providerType, 
                                       String redirectUri, 
                                       String state) {
        ClientRegistration registration = getClientRegistration(providerType);
        
        return UriComponentsBuilder
            .fromUriString(registration.getProviderDetails().getAuthorizationUri())
            .queryParam("client_id", registration.getClientId())
            .queryParam("redirect_uri", redirectUri)
            .queryParam("response_type", "code")
            .queryParam("scope", String.join(" ", registration.getScopes()))
            .queryParam("state", state)
            .build()
            .toUriString();
    }

    public OAuth2UserInfo exchangeCodeForUserInfo(ProviderType providerType, String code) {
        ClientRegistration registration = getClientRegistration(providerType);
        
        String accessToken = exchangeCodeForToken(registration, code);
        
        return fetchUserInfo(registration, accessToken, providerType);
    }

    private String exchangeCodeForToken(ClientRegistration registration, String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth(registration.getClientId(), registration.getClientSecret());

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", code);
        params.add("redirect_uri", "http://localhost:3000/oauth/callback");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        
        ResponseEntity<Map> response = restTemplate.postForEntity(
            registration.getProviderDetails().getTokenUri(),
            request,
            Map.class
        );

        return (String) response.getBody().get("access_token");
    }

    private OAuth2UserInfo fetchUserInfo(ClientRegistration registration, 
                                        String accessToken, 
                                        ProviderType providerType) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        
        HttpEntity<?> request = new HttpEntity<>(headers);
        
        ResponseEntity<Map> response = restTemplate.exchange(
            registration.getProviderDetails().getUserInfoEndpoint().getUri(),
            HttpMethod.GET,
            request,
            Map.class
        );

        return OAuth2UserInfoFactory.getOAuth2UserInfo(
            providerType.name().toLowerCase(), 
            response.getBody()
        );
    }

    private ClientRegistration getClientRegistration(ProviderType providerType) {
        String registrationId = providerType.name().toLowerCase();
        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId(registrationId);
        
        if (registration == null) {
            throw new IllegalArgumentException("Unknown provider: " + providerType);
        }
        
        return registration;
    }
}
