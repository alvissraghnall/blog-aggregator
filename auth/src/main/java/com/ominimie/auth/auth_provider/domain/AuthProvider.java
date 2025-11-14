package com.ominimie.auth.auth_provider.domain;

import com.ominimie.auth.proto.ProviderType;
import com.ominimie.auth.user.domain.User;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.DocumentReference;


@Document("authProviders")
@Getter
@Setter
public class AuthProvider {

    @Id
    private Long id;

    @Size(max = 255)
    private String passwordHash;

    @NotNull
    private ProviderType provider;

    @Size(max = 255)
    private String providerUserId;

    @Size(max = 255)
    private String providerUserEmail;

    @DocumentReference(lazy = true)
    @NotNull
    private User user;

    @CreatedDate
    private OffsetDateTime dateCreated;

    @LastModifiedDate
    private OffsetDateTime lastUpdated;

    @Version
    private Integer version;

}
