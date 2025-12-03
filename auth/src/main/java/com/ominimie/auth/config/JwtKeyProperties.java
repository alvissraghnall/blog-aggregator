package com.ominimie.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "security")
public class JwtKeyProperties {

    private String oauth2JwtPrivateKey;
    private String oauth2JwtPublicKey;

    public String getOauth2JwtPrivateKey() {
        return oauth2JwtPrivateKey;
    }

    public void setOauth2JwtPrivateKey(String oauth2JwtPrivateKey) {
        this.oauth2JwtPrivateKey = oauth2JwtPrivateKey;
    }

    public String getOauth2JwtPublicKey() {
        return oauth2JwtPublicKey;
    }

    public void setOauth2JwtPublicKey(String oauth2JwtPublicKey) {
        this.oauth2JwtPublicKey = oauth2JwtPublicKey;
    }
}
