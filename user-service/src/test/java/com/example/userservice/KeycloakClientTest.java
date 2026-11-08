package com.example.userservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.RestClient;

import com.example.userservice.keycloak.KeycloakClient;

/** Real KeycloakClient (no mocks) against a stub Keycloak. */
class KeycloakClientTest {

    private HttpServer server;
    private KeycloakClient client;
    private final List<String> requests = new CopyOnWriteArrayList<>();
    private volatile int tokenStatus = 200;
    private volatile String tokenBody = """
            {"access_token":"AT","expires_in":300,"refresh_token":"RT","refresh_expires_in":1800,"token_type":"Bearer","scope":"openid"}""";

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::handle);
        server.start();
        AppProperties props = new AppProperties("t", false, false, new AppProperties.Keycloak(
                "http://127.0.0.1:" + server.getAddress().getPort() + "/auth", "demo", "user-service", "sec", "comp-1"));
        client = new KeycloakClient(RestClient.builder(), props);
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private void handle(HttpExchange ex) throws IOException {
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        requests.add(ex.getRequestMethod() + " " + ex.getRequestURI().getPath() + " " + body + " auth="
                + ex.getRequestHeaders().getFirst("Authorization"));
        String path = ex.getRequestURI().getPath();
        int status;
        String resp;
        if (path.endsWith("/protocol/openid-connect/token")) {
            status = body.contains("grant_type=client_credentials") ? 200 : tokenStatus;
            resp = body.contains("grant_type=client_credentials") ? """
                    {"access_token":"SA","expires_in":300}""" : tokenBody;
        } else if (path.endsWith("/protocol/openid-connect/logout") || path.endsWith("/logout")) {
            status = 204; resp = "";
        } else {
            status = 404; resp = "";
        }
        byte[] bytes = resp.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) ex.getResponseBody().write(bytes);
        ex.close();
    }

    @Test
    void passwordGrantSendsClientCredentialsAndParsesTokens() {
        KeycloakClient.TokenResponse t = client.passwordGrant("alice", "p@ss&word");
        assertThat(t.accessToken()).isEqualTo("AT");
        assertThat(t.refreshToken()).isEqualTo("RT");
        assertThat(t.refreshExpiresIn()).isEqualTo(1800L);
        assertThat(requests.getFirst())
                .startsWith("POST /auth/realms/demo/protocol/openid-connect/token")
                .contains("grant_type=password", "client_id=user-service", "client_secret=sec",
                        "username=alice", "password=p%40ss%26word");
    }

    @Test
    void invalidGrantBecomesGeneric401() {
        tokenStatus = 401;
        tokenBody = "{\"error\":\"invalid_grant\",\"error_description\":\"Invalid user credentials\"}";
        assertThatThrownBy(() -> client.passwordGrant("alice", "x"))
                .isInstanceOfSatisfying(ApiException.class, e -> {
                    assertThat(e.status()).isEqualTo(HttpStatus.UNAUTHORIZED);
                    assertThat(e.code()).isEqualTo("invalid_credentials");
                });

        tokenStatus = 400;
        tokenBody = "{\"error\":\"invalid_grant\",\"error_description\":\"Account disabled\"}";
        assertThatThrownBy(() -> client.passwordGrant("alice", "x"))
                .isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.code()).isEqualTo("invalid_credentials"));
    }

    @Test
    void misconfigurationIsNotReportedAsBadPassword() {
        tokenStatus = 401;
        tokenBody = "{\"error\":\"unauthorized_client\",\"error_description\":\"Invalid client credentials\"}";
        assertThatThrownBy(() -> client.passwordGrant("alice", "x"))
                .isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.status()).isEqualTo(HttpStatus.BAD_GATEWAY));
    }

    @Test
    void unreachableKeycloakIs503() {
        server.stop(0);
        assertThatThrownBy(() -> client.passwordGrant("alice", "x"))
                .isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
    }

    @Test
    void logoutAllUsesServiceAccountAndFederatedId() {
        UUID id = UUID.randomUUID();
        client.logoutAllSessions(id);
        assertThat(requests).anySatisfy(r -> assertThat(r).contains("grant_type=client_credentials", "scope=kc-admin-api"));
        assertThat(requests.getLast())
                .startsWith("POST /auth/admin/realms/demo/users/f:comp-1:" + id + "/logout")
                .endsWith("auth=Bearer SA");
    }
}
