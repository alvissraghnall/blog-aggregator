package com.ominimie.auth.service.oauth2;

import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo (String registrationId, Map<String, Object> attributesMap) {
        switch (registrationId.toLowerCase()) {
            case "google":
                return new GoogleOAuth2UserInfo(attributesMap);
            case "github":
                return new GithubOAuth2UserInfo(attributesMap);
            case "apple":
                return new AppleOAuth2UserInfo(attributesMap);
            default:
                throw new IllegalArgumentException("Unsupported OAuth2 Provider: ".concat(registrationId));
        }
    }
}
