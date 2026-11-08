package com.example.authservice;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.test.context.DynamicPropertyRegistry;

/** Stand-in for a Keycloak realm key pair, plus a Keycloak-shaped token factory. */
final class TestKeys {

    static final String ISSUER = "http://localhost:8080/auth/realms/demo";
    static final KeyPair REALM = generate();
    static final KeyPair OTHER = generate();

    private TestKeys() {
    }

    /** Configure the app with the realm public key in admin-console format (bare base64). */
    static void register(DynamicPropertyRegistry registry) {
        registry.add("auth.jwt.public-key", () -> base64(REALM));
        registry.add("auth.jwt.issuer", () -> ISSUER);
        registry.add("auth.jwt.audiences", () -> "demo-api");
    }

    static String base64(KeyPair pair) {
        return Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
    }

    static String pem(KeyPair pair) {
        return "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pair.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----\n";
    }

    static RSAPublicKey publicKey(KeyPair pair) {
        return (RSAPublicKey) pair.getPublic();
    }

    /** A valid access token as Keycloak would issue it; customize claims via {@code tweak}. */
    static String token(KeyPair signer, Consumer<JWTClaimsSet.Builder> tweak) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("user-123")
                .audience(List.of("demo-api", "account"))
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .claim("typ", "Bearer")
                .claim("azp", "demo-client")
                .claim("preferred_username", "alice")
                .claim("email", "alice@example.com")
                .claim("realm_access", Map.of("roles", List.of("user")));
        tweak.accept(claims);
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test-kid").build(), claims.build());
            jwt.sign(new RSASSASigner((RSAPrivateKey) signer.getPrivate()));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    static String token() {
        return token(REALM, c -> { });
    }

    private static KeyPair generate() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
