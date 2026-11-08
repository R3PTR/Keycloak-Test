package com.example.backend;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Defense in depth: even though nginx already enforces authentication and the
 * admin role, the backend refuses /api requests without gateway identity and
 * re-checks the admin role on /api/admin.
 */
@Component
class GatewayUserFilter extends OncePerRequestFilter {

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        GatewayUser user = GatewayUser.fromHeaders(request);
        if (user == null) {
            reject(response, HttpStatus.UNAUTHORIZED);
            return;
        }
        if (request.getRequestURI().startsWith("/api/admin/") && !user.hasRole("admin")) {
            reject(response, HttpStatus.FORBIDDEN);
            return;
        }
        request.setAttribute(GatewayUser.ATTRIBUTE, user);
        chain.doFilter(request, response);
    }

    private static void reject(HttpServletResponse response, HttpStatus status) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + status.name().toLowerCase() + "\"}");
    }
}
