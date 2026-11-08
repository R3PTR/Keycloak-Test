package com.example.userservice.keycloak;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

import com.example.userservice.ApiException;
import com.example.userservice.AppProperties;

/**
 * Talks to Keycloak as the confidential client {@code user-service}:
 * <ul>
 *   <li>password grant / refresh / logout on the OIDC endpoints</li>
 *   <li>Admin REST API (service-account token) to end a user's sessions</li>
 * </ul>
 * Keycloak in turn validates the password by calling back into
 * {@code /internal/users/{id}/verify-password} through the User Storage SPI.
 */
@Component
public class KeycloakClient {

    private static final Logger log = LoggerFactory.getLogger(KeycloakClient.class);

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("expires_in") Long expiresIn,
            @JsonProperty("refresh_token") String refreshToken,
            // Wrappers: absent in some grants (client_credentials), and Jackson 3
            // rejects missing primitives by default.
            @JsonProperty("refresh_expires_in") Long refreshExpiresIn,
            @JsonProperty("token_type") String tokenType) {

        public long expiresInOr(long fallback) {
            return expiresIn == null ? fallback : expiresIn;
        }

        public long refreshExpiresInOr(long fallback) {
            return refreshExpiresIn == null || refreshExpiresIn <= 0 ? fallback : refreshExpiresIn;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record OAuthError(String error, @JsonProperty("error_description") String description) {
    }

    static final String ADMIN_API_SCOPE = "kc-admin-api";

    private final RestClient http;
    private final AppProperties.Keycloak kc;

    private volatile String serviceToken;
    private volatile Instant serviceTokenExpiry = Instant.EPOCH;

    public KeycloakClient(RestClient.Builder builder, AppProperties props) {
        this.kc = props.keycloak();
        // JDK HttpClient: unlike HttpURLConnection it doesn't choke on 401 responses
        // to streamed POSTs (Keycloak answers bad credentials with 401).
        JdkClientHttpRequestFactory rf = new JdkClientHttpRequestFactory(
                java.net.http.HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build());
        rf.setReadTimeout(Duration.ofSeconds(10));
        this.http = builder.requestFactory(rf).build();
    }

    /** Resource Owner Password Credentials grant. Wrong credentials → 401 invalid_credentials. */
    public TokenResponse passwordGrant(String username, String password) {
        MultiValueMap<String, String> form = clientForm();
        form.add("grant_type", "password");
        form.add("username", username);
        form.add("password", password);
        form.add("scope", "openid");
        return tokenRequest(form, "invalid_credentials", "Invalid username or password");
    }

    /** Refresh grant. Expired/revoked refresh token → 401 session_expired. */
    public TokenResponse refresh(String refreshToken) {
        MultiValueMap<String, String> form = clientForm();
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshToken);
        return tokenRequest(form, "session_expired", "Session expired, please sign in again");
    }

    /** Ends the Keycloak SSO session the refresh token belongs to. Best effort. */
    public void logout(String refreshToken) {
        MultiValueMap<String, String> form = clientForm();
        form.add("refresh_token", refreshToken);
        try {
            http.post().uri(kc.realmUrl() + "/protocol/openid-connect/logout")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED).body(form)
                    .retrieve().toBodilessEntity();
        } catch (RestClientResponseException e) {
            // 400 = token already invalid/expired: the session is gone either way.
            log.debug("Keycloak logout returned {}", e.getStatusCode());
        } catch (RestClientException e) {
            throw unavailable(e);
        }
    }

    /** Ends all sessions of a user (admin API, needs realm-management/manage-users). */
    public void logoutAllSessions(UUID userId) {
        String id = kc.keycloakUserId(userId);
        try {
            http.post().uri(kc.adminRealmUrl() + "/users/{id}/logout", id)
                    .headers(h -> h.setBearerAuth(serviceAccountToken()))
                    .retrieve().toBodilessEntity();
        } catch (RestClientResponseException e) {
            if (e.getStatusCode().value() == 404) {
                return; // user never logged in / unknown to Keycloak
            }
            if (e.getStatusCode().value() == 401) {
                serviceToken = null; // e.g. Keycloak restarted with new keys; refetch next time
            }
            log.warn("Could not end sessions of {}: {} {}", id, e.getStatusCode(), e.getResponseBodyAsString());
            throw new ApiException(HttpStatus.BAD_GATEWAY, "sessions_not_ended", "Could not end sessions in Keycloak");
        } catch (RestClientException e) {
            throw unavailable(e);
        }
    }

    // ------------------------------------------------------------------------

    private TokenResponse tokenRequest(MultiValueMap<String, String> form, String errorCode, String message) {
        try {
            return http.post().uri(kc.realmUrl() + "/protocol/openid-connect/token")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED).body(form)
                    .retrieve().body(TokenResponse.class);
        } catch (RestClientResponseException e) {
            OAuthError err = parseError(e);
            if (isClientError(e.getStatusCode()) && err != null && "invalid_grant".equals(err.error())) {
                log.debug("Keycloak rejected grant: {}", err.description());
                // Same response for unknown user, wrong password, disabled or locked account.
                throw ApiException.unauthorized(errorCode, message);
            }
            log.warn("Keycloak token endpoint returned {}: {}", e.getStatusCode(), e.getResponseBodyAsString());
            throw new ApiException(HttpStatus.BAD_GATEWAY, "keycloak_error", "Login is currently unavailable");
        } catch (RestClientException e) {
            throw unavailable(e);
        }
    }

    private String serviceAccountToken() {
        if (serviceToken != null && Instant.now().isBefore(serviceTokenExpiry)) {
            return serviceToken;
        }
        synchronized (this) {
            if (serviceToken == null || !Instant.now().isBefore(serviceTokenExpiry)) {
                MultiValueMap<String, String> form = clientForm();
                form.add("grant_type", "client_credentials");
                // Keycloak 26.x Admin API requires the kc-admin-api scope (adds its audience).
                form.add("scope", ADMIN_API_SCOPE);
                TokenResponse t = http.post().uri(kc.realmUrl() + "/protocol/openid-connect/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED).body(form)
                        .retrieve().body(TokenResponse.class);
                serviceToken = t.accessToken();
                serviceTokenExpiry = Instant.now().plusSeconds(Math.max(t.expiresInOr(60) - 30, 5));
            }
            return serviceToken;
        }
    }

    private MultiValueMap<String, String> clientForm() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", kc.clientId());
        form.add("client_secret", kc.clientSecret());
        return form;
    }

    private static boolean isClientError(HttpStatusCode code) {
        return code.value() == 400 || code.value() == 401;
    }

    private static OAuthError parseError(RestClientResponseException e) {
        try {
            Map<?, ?> body = e.getResponseBodyAs(Map.class);
            return body == null ? null
                    : new OAuthError((String) body.get("error"), (String) body.get("error_description"));
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static ApiException unavailable(RestClientException e) {
        log.warn("Keycloak unreachable: {}", e.getMessage());
        return new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "keycloak_unavailable", "Login is currently unavailable");
    }
}
