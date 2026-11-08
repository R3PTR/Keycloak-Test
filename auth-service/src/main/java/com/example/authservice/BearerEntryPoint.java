package com.example.authservice;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * RFC 6750 challenge without Spring's default RFC 9728 {@code resource_metadata}
 * parameter, which would expose this service's internal hostname to clients
 * (nginx forwards this header verbatim).
 */
class BearerEntryPoint implements AuthenticationEntryPoint {

    private final String realm;

    BearerEntryPoint(String realm) {
        this.realm = realm;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException ex) throws IOException {
        StringBuilder challenge = new StringBuilder("Bearer realm=\"").append(realm).append('"');
        if (ex instanceof OAuth2AuthenticationException oauth2 && oauth2.getError() instanceof BearerTokenError error) {
            // Only the error code: descriptions can contain internal detail.
            challenge.append(", error=\"").append(error.getErrorCode()).append('"');
        }
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, challenge.toString());
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
    }
}
