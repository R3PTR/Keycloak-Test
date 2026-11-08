package com.example.authservice;

import java.net.URI;
import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * @param issuer     expected {@code iss} claim (the public Keycloak realm URL)
 * @param audiences  at least one must be present in {@code aud}
 * @param publicKey  realm RS256 public key, either as shown in the Keycloak admin
 *                   console (base64 DER) or PEM. If empty, it is fetched from {@code realmUri}.
 * @param realmUri   realm endpoint returning {@code {"public_key": "..."}}
 * @param clockSkew  tolerance for {@code exp}/{@code nbf}
 */
@ConfigurationProperties("auth.jwt")
public record JwtProperties(
        String issuer,
        List<String> audiences,
        String publicKey,
        URI realmUri,
        @DefaultValue("30s") Duration clockSkew) {
}
