package com.example.keycloak.userstorage;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** User as returned by the user-service internal API. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RemoteUser(
        String id,
        String username,
        String email,
        String firstName,
        String lastName,
        boolean enabled,
        boolean emailVerified,
        List<String> roles,
        long createdAt) {

    public List<String> roles() {
        return roles == null ? List.of() : roles;
    }
}
