package com.ominimie.auth.api_key.model;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;

import com.ominimie.auth.api_key.service.ApiKeyService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Map;
import org.springframework.web.servlet.HandlerMapping;


/**
 * Validate that the key value isn't taken yet.
 */
@Target({ FIELD, METHOD, ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Constraint(
        validatedBy = ApiKeyKeyUnique.ApiKeyKeyUniqueValidator.class
)
public @interface ApiKeyKeyUnique {

    String message() default "{Exists.apiKey.key}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class ApiKeyKeyUniqueValidator implements ConstraintValidator<ApiKeyKeyUnique, String> {

        private final ApiKeyService apiKeyService;
        private final HttpServletRequest request;

        public ApiKeyKeyUniqueValidator(final ApiKeyService apiKeyService,
                final HttpServletRequest request) {
            this.apiKeyService = apiKeyService;
            this.request = request;
        }

        @Override
        public boolean isValid(final String value, final ConstraintValidatorContext cvContext) {
            if (value == null) {
                // no value present
                return true;
            }
            @SuppressWarnings("unchecked") final Map<String, String> pathVariables =
                    ((Map<String, String>)request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE));
            final String currentId = pathVariables.get("id");
            if (currentId != null && value.equalsIgnoreCase(apiKeyService.get(Long.parseLong(currentId)).getKey())) {
                // value hasn't changed
                return true;
            }
            return !apiKeyService.keyExists(value);
        }

    }

}
