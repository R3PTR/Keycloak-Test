package com.example.userservice;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.util.StringUtils;

@ConfigurationProperties("app")
public record AppProperties(
        String internalToken,
        @DefaultValue("false") boolean seedDemoUsers,
        @DefaultValue("false") boolean cookieSecure,
        Keycloak keycloak) {

    public AppProperties {
        if (!StringUtils.hasText(internalToken)) {
            throw new IllegalStateException("app.internal-token (USER_SERVICE_INTERNAL_TOKEN) must be set");
        }
    }

    public record Keycloak(String serverUrl, String realm, String clientId, String clientSecret,
                           String federationComponentId) {

        public String realmUrl() {
            return trim(serverUrl) + "/realms/" + realm;
        }

        public String adminRealmUrl() {
            return trim(serverUrl) + "/admin/realms/" + realm;
        }

        /** Keycloak's id for a federated user: {@code f:<componentId>:<externalId>}. */
        public String keycloakUserId(java.util.UUID id) {
            return "f:" + federationComponentId + ":" + id;
        }

        private static String trim(String url) {
            return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
        }
    }
}
