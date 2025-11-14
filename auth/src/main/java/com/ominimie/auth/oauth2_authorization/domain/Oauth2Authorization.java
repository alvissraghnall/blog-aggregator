package com.ominimie.auth.oauth2_authorization.domain;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Map;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.mapping.Document;

@Document("oauth2Authorizations")
@Getter
@Setter
@Builder
public class Oauth2Authorization {

    @Id
    private Long id;

    @NotNull
    @Size(max = 255)
    private String registeredClientId;

    @NotNull
    @Size(max = 255)
    private String principalName;

    @NotNull
    @Size(max = 255)
    private String authorizationGrantType;

    @Size(max = 2000)
    private String attributes;

    @Size(max = 500)
    private String state;

    @Size(max = 1000)
    private String authorizationCodeValue;
    private Instant authorizationCodeIssuedAt;
    private Instant authorizationCodeExpiresAt;
    @Size(max = 1000)
    private String authorizationCodeMetadata;

    @Size(max = 1000)
    private String accessTokenValue;
    private Instant accessTokenIssuedAt;
    private Instant accessTokenExpiresAt;
    @Size(max = 1000)
    private String accessTokenMetadata;
    @Size(max = 255)
    private String accessTokenType;
    @Size(max = 1000)
    private String accessTokenScopes;

    @Size(max = 1000)
    private String oidcIdTokenValue;
    private Instant oidcIdTokenIssuedAt;
    private Instant oidcIdTokenExpiresAt;
    @Size(max = 1000)
    private String oidcIdTokenMetadata;
    private String oidcTokenClaims;

    @Size(max = 1000)
    private String refreshTokenValue;
    private Instant refreshTokenIssuedAt;
    private Instant refreshTokenExpiresAt;
    @Size(max = 1000)
    private String refreshTokenMetadata;

    @CreatedDate
    private OffsetDateTime dateCreated;

    @LastModifiedDate
    private OffsetDateTime lastUpdated;

    @Version
    private Integer version;
}
