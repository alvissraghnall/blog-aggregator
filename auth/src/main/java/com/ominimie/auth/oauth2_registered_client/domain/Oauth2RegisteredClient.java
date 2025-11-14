package com.ominimie.auth.oauth2_registered_client.domain;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Set;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;


@Document("oauth2RegisteredClients")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Oauth2RegisteredClient {

    @Id
    private Long id;

    private Map<String, Object> tokenSettings;

    private Map<String, Object> clientSettings;

    private Set<@Size(max = 255) String> scopes;

    @NotNull
    private Set<@Size(max = 255) String> redirectUris;

    @NotNull
    private Set<@Size(max = 255) String> authorizationGrantTypes;

    private Set<String> clientAuthenticationMethods;

    @Indexed(unique = true)
    @NotNull
    @Size(max = 255)
    private String clientId;

    @NotNull
    @Size(max = 255)
    private String clientSecret;

    @CreatedDate
    private OffsetDateTime dateCreated;

    @LastModifiedDate
    private OffsetDateTime lastUpdated;

    @Version
    private Integer version;

}
