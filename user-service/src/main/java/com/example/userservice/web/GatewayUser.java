package com.example.userservice.web;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Identity set by nginx (from the auth service) after JWT validation. Trusted only
 * because user-service is reachable solely through nginx and the Docker network.
 *
 * @param subject Keycloak {@code sub}; for federated users {@code f:<componentId>:<uuid>}
 */
public record GatewayUser(String subject, String username, List<String> roles) {

    public static final String ATTRIBUTE = "gatewayUser";

    static GatewayUser fromHeaders(HttpServletRequest request) {
        String sub = request.getHeader("X-User-Id");
        if (sub == null || sub.isBlank()) {
            return null;
        }
        String roles = request.getHeader("X-User-Roles");
        return new GatewayUser(sub, request.getHeader("X-User-Name"),
                roles == null || roles.isBlank() ? List.of()
                        : Arrays.stream(roles.split(",")).map(String::trim).filter(r -> !r.isEmpty()).toList());
    }

    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    /** The user-service UUID, if the subject is a user federated through our component. */
    public Optional<UUID> userId(String federationComponentId) {
        String prefix = "f:" + federationComponentId + ":";
        if (!subject.startsWith(prefix)) {
            return Optional.empty();
        }
        try {
            return Optional.of(UUID.fromString(subject.substring(prefix.length())));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
