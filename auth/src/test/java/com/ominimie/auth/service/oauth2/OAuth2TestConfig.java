package com.ominimie.auth.service.oauth2;

import com.ominimie.auth.proto.ProviderType;

import java.util.HashMap;
import java.util.Map;

import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

@TestConfiguration
public class OAuth2TestConfig {

    @Bean
    @Primary
    public OAuth2Service mockOAuth2Service() {
        OAuth2Service mockService = Mockito.mock(OAuth2Service.class);
        
        Mockito.when(mockService.buildAuthorizationUrl(
            Mockito.any(ProviderType.class), 
            Mockito.anyString(), 
            Mockito.anyString()
        )).thenReturn("https://accounts.google.com/o/oauth2/v2/auth?mock=true");
        
        Map<String, Object> attrs = new HashMap<>();

        attrs.put("sub", "google_user_001");
        attrs.put("name", "Haha User");
        attrs.put("email", "google@google.io");
        
        OAuth2UserInfo mockUserInfo = new GoogleOAuth2UserInfo(attrs);

        Mockito.when(mockService.exchangeCodeForUserInfo(
            Mockito.any(ProviderType.class), 
            Mockito.anyString()
        )).thenReturn(mockUserInfo);
        
        return mockService;
    }
}
