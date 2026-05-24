package app.zylos.security.opa;

import java.util.List;
import java.util.Map;

import org.jspecify.annotations.Nullable;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Common OPA decision shape: {@code {"allow": true|false, "reasons": [...],
 * "obligations": {...}}}.
 *
 * <p>This is the recommended canonical shape for Zylos OPA policies but is
 * not required; services using a different shape can pass their own type
 * to {@link OpaClient#evaluate}.
 *
 * @param allow       whether the action is permitted ({@code null} when the
 *                    policy doesn't return this field — treated as deny by
 *                    {@link OpaClient#check})
 * @param reasons     human-readable reasons for the decision; may be {@code null}
 * @param obligations key-value obligations the caller must enforce
 *                    post-decision (e.g., column-level masking instructions); may be
 *                    {@code null}
 */
public record OpaDecisionResponse(
        @JsonProperty("allow") @Nullable Boolean allow,
        @JsonProperty("reasons") @Nullable List<String> reasons,
        @JsonProperty("obligations") @Nullable Map<String, Object> obligations) {}
