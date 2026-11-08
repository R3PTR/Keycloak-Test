package com.example.backend;

import java.util.Arrays;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Identity established by the gateway. nginx sets these headers from the auth
 * service's response after the JWT was verified and always overwrites any
 * client-supplied values, so they are trustworthy <em>only</em> because this
 * service is reachable exclusively through nginx (no published port).
 */
public record GatewayUser(String id, String username, String email, List<String> roles) {

    static final String ATTRIBUTE = "gatewayUser";

    static GatewayUser fromHeaders(HttpServletRequest request) {
        String id = request.getHeader("X-User-Id");
        if (id == null || id.isBlank()) {
            return null;
        }
        String roles = request.getHeader("X-User-Roles");
        return new GatewayUser(
                id,
                nullToEmpty(request.getHeader("X-User-Name")),
                nullToEmpty(request.getHeader("X-User-Email")),
                roles == null || roles.isBlank() ? List.of()
                        : Arrays.stream(roles.split(",")).map(String::trim).filter(r -> !r.isEmpty()).toList());
    }

    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
