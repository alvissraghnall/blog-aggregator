package com.ominimie.auth.password_reset_token.domain;

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


@Document("passwordResetTokens")
@Getter
@Setter
public class PasswordResetToken {

    @Id
    private Long id;

    @Indexed(unique = true)
    @NotNull
    @Size(max = 255)
    private String token;

    @NotNull
    private OffsetDateTime expiresAt;

    @NotNull
    private Boolean used;

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
