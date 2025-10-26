package com.ominimie.auth.api_key.service;

import com.ominimie.auth.api_key.domain.ApiKey;
import com.ominimie.auth.api_key.model.ApiKeyDTO;
import com.ominimie.auth.api_key.repos.ApiKeyRepository;
import com.ominimie.auth.events.BeforeDeleteUser;
import com.ominimie.auth.user.domain.User;
import com.ominimie.auth.user.repos.UserRepository;
import com.ominimie.auth.util.NotFoundException;
import com.ominimie.auth.util.ReferencedException;
import java.util.List;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;


@Service
public class ApiKeyService {

    private final ApiKeyRepository apiKeyRepository;
    private final UserRepository userRepository;

    public ApiKeyService(final ApiKeyRepository apiKeyRepository,
            final UserRepository userRepository) {
        this.apiKeyRepository = apiKeyRepository;
        this.userRepository = userRepository;
    }

    public List<ApiKeyDTO> findAll() {
        final List<ApiKey> apiKeys = apiKeyRepository.findAll(Sort.by("id"));
        return apiKeys.stream()
                .map(apiKey -> mapToDTO(apiKey, new ApiKeyDTO()))
                .toList();
    }

    public ApiKeyDTO get(final Long id) {
        return apiKeyRepository.findById(id)
                .map(apiKey -> mapToDTO(apiKey, new ApiKeyDTO()))
                .orElseThrow(NotFoundException::new);
    }

    public Long create(final ApiKeyDTO apiKeyDTO) {
        final ApiKey apiKey = new ApiKey();
        mapToEntity(apiKeyDTO, apiKey);
        return apiKeyRepository.save(apiKey).getId();
    }

    public void update(final Long id, final ApiKeyDTO apiKeyDTO) {
        final ApiKey apiKey = apiKeyRepository.findById(id)
                .orElseThrow(NotFoundException::new);
        mapToEntity(apiKeyDTO, apiKey);
        apiKeyRepository.save(apiKey);
    }

    public void delete(final Long id) {
        final ApiKey apiKey = apiKeyRepository.findById(id)
                .orElseThrow(NotFoundException::new);
        apiKeyRepository.delete(apiKey);
    }

    private ApiKeyDTO mapToDTO(final ApiKey apiKey, final ApiKeyDTO apiKeyDTO) {
        apiKeyDTO.setId(apiKey.getId());
        apiKeyDTO.setKey(apiKey.getKey());
        apiKeyDTO.setName(apiKey.getName());
        apiKeyDTO.setExpiresAt(apiKey.getExpiresAt());
        apiKeyDTO.setIsActive(apiKey.getIsActive());
        apiKeyDTO.setUser(apiKey.getUser() == null ? null : apiKey.getUser().getId());
        return apiKeyDTO;
    }

    private ApiKey mapToEntity(final ApiKeyDTO apiKeyDTO, final ApiKey apiKey) {
        apiKey.setKey(apiKeyDTO.getKey());
        apiKey.setName(apiKeyDTO.getName());
        apiKey.setExpiresAt(apiKeyDTO.getExpiresAt());
        apiKey.setIsActive(apiKeyDTO.getIsActive());
        final User user = apiKeyDTO.getUser() == null ? null : userRepository.findById(apiKeyDTO.getUser())
                .orElseThrow(() -> new NotFoundException("user not found"));
        apiKey.setUser(user);
        return apiKey;
    }

    public boolean keyExists(final String key) {
        return apiKeyRepository.existsByKeyIgnoreCase(key);
    }

    @EventListener(BeforeDeleteUser.class)
    public void on(final BeforeDeleteUser event) {
        final ReferencedException referencedException = new ReferencedException();
        final ApiKey userApiKey = apiKeyRepository.findFirstByUserId(event.getId());
        if (userApiKey != null) {
            referencedException.setKey("user.apiKey.user.referenced");
            referencedException.addParam(userApiKey.getId());
            throw referencedException;
        }
    }

}
