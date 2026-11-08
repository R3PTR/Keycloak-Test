package com.example.authservice;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    /**
     * Signature, expiry/nbf, issuer and audience are all validated by Spring's
     * JwtDecoder (configured via spring.security.oauth2.resourceserver.jwt.*).
     * Any failure yields 401 with a WWW-Authenticate header, which nginx relays.
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health/**", "/actuator/health").permitAll()
                        .requestMatchers("/validate").authenticated()
                        .anyRequest().denyAll())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                        .authenticationEntryPoint(new BearerEntryPoint("demo")))
                .exceptionHandling(e -> e.authenticationEntryPoint(new BearerEntryPoint("demo")))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable())
                .requestCache(cache -> cache.disable())
                .build();
    }
}
