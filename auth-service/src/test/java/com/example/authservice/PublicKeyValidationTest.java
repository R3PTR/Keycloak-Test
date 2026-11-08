package com.example.authservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/** Real signed tokens through the real decoder (no security test shortcuts). */
@SpringBootTest
@AutoConfigureMockMvc
class PublicKeyValidationTest {

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        TestKeys.register(registry);
    }

    @Autowired
    MockMvc mvc;

    private ResultActions call(String token) throws Exception {
        return mvc.perform(get("/validate").header("Authorization", "Bearer " + token));
    }

    @Test
    void acceptsTokenSignedWithRealmKey() throws Exception {
        call(TestKeys.token())
                .andExpect(status().isOk())
                .andExpect(header().string("X-User-Id", "user-123"))
                .andExpect(header().string("X-User-Name", "alice"));
    }

    @Test
    void rejectsTokenSignedWithDifferentKey() throws Exception {
        call(TestKeys.token(TestKeys.OTHER, c -> { }))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer realm=\"demo\", error=\"invalid_token\""));
    }

    @Test
    void rejectsExpiredToken() throws Exception {
        call(TestKeys.token(TestKeys.REALM, c -> c.expirationTime(Date.from(Instant.now().minusSeconds(120)))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsWrongIssuer() throws Exception {
        call(TestKeys.token(TestKeys.REALM, c -> c.issuer("http://evil.example/realms/demo")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsWrongAudience() throws Exception {
        call(TestKeys.token(TestKeys.REALM, c -> c.audience("account")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsNonAccessToken() throws Exception {
        call(TestKeys.token(TestKeys.REALM, c -> c.claim("typ", "ID")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsAlgNone() throws Exception {
        String[] parts = TestKeys.token().split("\\.");
        String header = b64("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        call(header + "." + parts[1] + ".").andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsHs256SignedWithPublicKeyAsSecret() throws Exception {
        // Classic algorithm-confusion attack: HMAC "signed" with the public key bytes.
        String[] parts = TestKeys.token().split("\\.");
        String header = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(TestKeys.REALM.getPublic().getEncoded(), "HmacSHA256"));
        String sig = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal((header + "." + parts[1]).getBytes(StandardCharsets.US_ASCII)));
        call(header + "." + parts[1] + "." + sig).andExpect(status().isUnauthorized());
    }

    @Test
    void parsesBothKeycloakKeyFormats() {
        assertThat(KeycloakPublicKeys.parse(TestKeys.base64(TestKeys.REALM))).isEqualTo(TestKeys.publicKey(TestKeys.REALM));
        assertThat(KeycloakPublicKeys.parse(TestKeys.pem(TestKeys.REALM))).isEqualTo(TestKeys.publicKey(TestKeys.REALM));
        assertThatThrownBy(() -> KeycloakPublicKeys.parse("not-a-key")).isInstanceOf(IllegalStateException.class);
    }

    private static String b64(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
