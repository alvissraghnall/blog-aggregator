package com.ominimie.auth.api_key.domain;

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
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.DocumentReference;


@Document("apiKeys")
@Getter
@Setter
public class ApiKey {

    @Id
    private Long id;

    @Indexed(unique = true)
    @NotNull
    @Size(max = 255)
    private String key;

    @NotNull
    @Size(max = 255)
    private String name;

    @NotNull
    private OffsetDateTime expiresAt;

    @NotNull
    private Boolean isActive;

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
