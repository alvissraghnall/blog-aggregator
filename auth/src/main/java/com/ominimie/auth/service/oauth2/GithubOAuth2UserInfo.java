package com.ominimie.auth.service.oauth2;

import java.util.Map;

import lombok.experimental.SuperBuilder;

@SuperBuilder
public class GithubOAuth2UserInfo extends OAuth2UserInfo {
    
    public GithubOAuth2UserInfo (Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("id").toString();
    }

    @Override
    public String getName() {
        String name = (String) attributes.get("name");
        return name != null ? name : (String) attributes.get("login");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }
}
