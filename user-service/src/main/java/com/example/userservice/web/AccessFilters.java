package com.example.userservice.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.userservice.AppProperties;

/**
 * Access rules (no Spring Security on purpose: authentication is done upstream):
 * <ul>
 *   <li>{@code /internal/**}: only with the shared {@code X-Internal-Token} (Keycloak SPI)</li>
 *   <li>{@code /users/me/**}: gateway identity required</li>
 *   <li>{@code /users/admin/**}: gateway identity with role admin</li>
 *   <li>{@code /users/login|refresh|logout|register}: public</li>
 * </ul>
 * nginx enforces the same for the public paths; this is defense in depth.
 */
@Configuration
class AccessFilters {

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    FilterRegistrationBean<InternalTokenFilter> internalTokenFilter(AppProperties props) {
        FilterRegistrationBean<InternalTokenFilter> reg = new FilterRegistrationBean<>(new InternalTokenFilter(props.internalToken()));
        reg.addUrlPatterns("/internal/*");
        reg.setOrder(1);
        return reg;
    }

    @Bean
    FilterRegistrationBean<GatewayUserFilter> gatewayUserFilter() {
        FilterRegistrationBean<GatewayUserFilter> reg = new FilterRegistrationBean<>(new GatewayUserFilter());
        reg.addUrlPatterns("/users/me", "/users/me/*", "/users/admin/*");
        reg.setOrder(2);
        return reg;
    }

    static final class InternalTokenFilter extends OncePerRequestFilter {
        private final byte[] expected;

        InternalTokenFilter(String token) {
            this.expected = token.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                throws ServletException, IOException {
            String given = req.getHeader("X-Internal-Token");
            if (given == null || !MessageDigest.isEqual(expected, given.getBytes(StandardCharsets.UTF_8))) {
                reject(res, HttpStatus.UNAUTHORIZED, "invalid_internal_token");
                return;
            }
            chain.doFilter(req, res);
        }
    }

    static final class GatewayUserFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                throws ServletException, IOException {
            GatewayUser user = GatewayUser.fromHeaders(req);
            if (user == null) {
                reject(res, HttpStatus.UNAUTHORIZED, "unauthorized");
                return;
            }
            if (req.getRequestURI().startsWith("/users/admin/") && !user.hasRole("admin")) {
                reject(res, HttpStatus.FORBIDDEN, "forbidden");
                return;
            }
            req.setAttribute(GatewayUser.ATTRIBUTE, user);
            chain.doFilter(req, res);
        }
    }

    static void reject(HttpServletResponse res, HttpStatus status, String code) throws IOException {
        res.setStatus(status.value());
        res.setContentType(MediaType.APPLICATION_JSON_VALUE);
        res.getWriter().write("{\"error\":\"" + code + "\"}");
    }
}
