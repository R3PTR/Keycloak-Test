package com.example.authservice;

import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.StringUtils;

/**
 * Verifies tokens against Keycloak's realm RSA public key.
 *
 * <p>Defining a {@link JwtDecoder} bean replaces Spring Boot's auto-configured
 * one, so every claim check is explicit here:
 * <ul>
 *   <li>signature: RS256 with the realm public key (other algorithms rejected)</li>
 *   <li>{@code exp} / {@code nbf} with clock skew</li>
 *   <li>{@code iss} equals the configured issuer</li>
 *   <li>{@code aud} contains one of the configured audiences</li>
 *   <li>{@code typ} is {@code Bearer} (Keycloak access token; rejects ID/refresh tokens)</li>
 * </ul>
 *
 * <p>Trade-off vs. JWKS: the key is loaded once at startup. After rotating the
 * realm key in Keycloak, restart this service (or update {@code AUTH_PUBLIC_KEY}).
 */
@Configuration
@EnableConfigurationProperties(JwtProperties.class)
class JwtDecoderConfig {

    private static final Logger log = LoggerFactory.getLogger(JwtDecoderConfig.class);

    @Bean
    JwtDecoder jwtDecoder(JwtProperties props) {
        RSAPublicKey key = loadKey(props);

        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(key)
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(validator(props));
        return decoder;
    }

    static RSAPublicKey loadKey(JwtProperties props) {
        RSAPublicKey key;
        String source;
        if (StringUtils.hasText(props.publicKey())) {
            key = KeycloakPublicKeys.parse(props.publicKey());
            source = "auth.jwt.public-key";
        } else if (props.realmUri() != null) {
            key = KeycloakPublicKeys.fetch(props.realmUri(), 20, Duration.ofSeconds(3));
            source = props.realmUri().toString();
        } else {
            throw new IllegalStateException("Configure auth.jwt.public-key or auth.jwt.realm-uri");
        }
        log.info("Verifying JWTs with RSA public key from {} ({} bit, sha256 {}…)",
                source, key.getModulus().bitLength(), KeycloakPublicKeys.fingerprint(key));
        return key;
    }

    static OAuth2TokenValidator<Jwt> validator(JwtProperties props) {
        if (!StringUtils.hasText(props.issuer())) {
            throw new IllegalStateException("auth.jwt.issuer must be set");
        }
        List<String> audiences = props.audiences() == null ? List.of() : props.audiences();
        if (audiences.isEmpty()) {
            throw new IllegalStateException("auth.jwt.audiences must not be empty");
        }
        return new DelegatingOAuth2TokenValidator<>(
                new JwtTimestampValidator(props.clockSkew()),
                new JwtIssuerValidator(props.issuer()),
                new JwtClaimValidator<Collection<String>>(JwtClaimNames.AUD,
                        aud -> aud != null && aud.stream().anyMatch(audiences::contains)),
                new JwtClaimValidator<String>("typ", "Bearer"::equals));
    }
}
