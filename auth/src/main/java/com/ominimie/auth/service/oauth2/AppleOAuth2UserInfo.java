package com.ominimie.auth.service.oauth2;

import java.util.Map;

import lombok.experimental.SuperBuilder;

@SuperBuilder
public class AppleOAuth2UserInfo extends OAuth2UserInfo {

    
    public AppleOAuth2UserInfo (Map<String, Object> attributes) {
        super(attributes);
    }
    
    @Override
    public String getId() {
        return (String) attributes.get("sub");
    }

    @Override
    public String getName() {
        String name = (String) attributes.get("name");
        return name != null ? name : (String) attributes.get("email");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }
}
