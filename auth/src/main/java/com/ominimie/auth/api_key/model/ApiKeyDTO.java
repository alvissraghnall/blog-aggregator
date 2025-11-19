package com.ominimie.auth.api_key.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.OffsetDateTime;
import java.util.UUID;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class ApiKeyDTO {

    private Long id;

    @NotNull
    @Size(max = 255)
    private String key;

    @NotNull
    @Size(max = 255)
    private String name;

    @NotNull
    private OffsetDateTime expiresAt;

    @NotNull
    @JsonProperty("isActive")
    private Boolean isActive;

    @NotNull
    private UUID user;

}
