package com.ominimie.auth.service.oauth2;

import java.util.Map;

import lombok.RequiredArgsConstructor;
import lombok.experimental.SuperBuilder;

@RequiredArgsConstructor
@SuperBuilder
public abstract class OAuth2UserInfo {
    protected final Map<String, Object> attributes;

    public abstract String getId();
    public abstract String getEmail();
    public abstract String getName();
}
