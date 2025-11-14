package com.ominimie.auth.service.oauth2;

import com.ominimie.auth.user.domain.User;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class OAuth2TokenIntrospection {
    private boolean active;
    private User user;
}
