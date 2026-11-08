package com.example.authservice;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/** Obtains and parses the realm's RSA public key. */
final class KeycloakPublicKeys {

    private static final Logger log = LoggerFactory.getLogger(KeycloakPublicKeys.class);

    private KeycloakPublicKeys() {
    }

    /**
     * Parses a key in either format Keycloak hands out: the bare base64
     * SubjectPublicKeyInfo from the admin console / realm endpoint, or PEM
     * ({@code -----BEGIN PUBLIC KEY-----}).
     */
    static RSAPublicKey parse(String key) {
        String base64 = key
                .replaceAll("-----(BEGIN|END) PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        try {
            byte[] der = Base64.getDecoder().decode(base64);
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (IllegalArgumentException | GeneralSecurityException | ClassCastException e) {
            throw new IllegalStateException("auth.jwt.public-key is not a valid RSA public key", e);
        }
    }

    /**
     * Reads {@code public_key} from the realm endpoint (e.g.
     * {@code http://keycloak:8080/auth/realms/demo}). This is the realm's active
     * RS256 signing key. Retries so startup tolerates Keycloak still booting.
     */
    static RSAPublicKey fetch(URI realmUri, int attempts, Duration delay) {
        RestClient client = RestClient.create();
        RuntimeException last = null;
        for (int i = 1; i <= attempts; i++) {
            try {
                Map<String, Object> realm = client.get().uri(realmUri).retrieve()
                        .body(new ParameterizedTypeReference<>() { });
                if (realm != null && realm.get("public_key") instanceof String key && !key.isBlank()) {
                    return parse(key);
                }
                last = new IllegalStateException("No 'public_key' in response from " + realmUri);
            } catch (RestClientException e) {
                last = e;
            }
            log.warn("Fetching realm public key from {} failed (attempt {}/{}): {}", realmUri, i, attempts, last.getMessage());
            sleep(delay);
        }
        throw new IllegalStateException("Could not obtain realm public key from " + realmUri, last);
    }

    /** Short SHA-256 fingerprint for logs, to compare with the key in the admin console. */
    static String fingerprint(RSAPublicKey key) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(key.getEncoded());
            return HexFormat.ofDelimiter(":").formatHex(digest, 0, 8);
        } catch (GeneralSecurityException e) {
            return "?";
        }
    }

    private static void sleep(Duration delay) {
        try {
            Thread.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for Keycloak", e);
        }
    }
}
