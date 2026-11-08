package com.example.keycloak.userstorage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.UserModel;

class UserServiceClientTest {

    private static final String ALICE = """
            {"id":"11111111-1111-1111-1111-111111111111","username":"alice","email":"alice@example.com",
             "firstName":"Alice","lastName":"User","enabled":true,"emailVerified":true,
             "roles":["user"],"createdAt":1700000000000,"somethingNew":"ignored"}""";

    private HttpServer server;
    private UserServiceClient client;
    private final List<String> seenTokens = new CopyOnWriteArrayList<>();
    private final List<String> seenBodies = new CopyOnWriteArrayList<>();

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/internal/users", this::handle);
        server.start();
        client = new UserServiceClient(HttpClient.newHttpClient(),
                "http://127.0.0.1:" + server.getAddress().getPort() + "/", "s3cret", Duration.ofSeconds(2));
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private void handle(HttpExchange ex) throws IOException {
        seenTokens.add(ex.getRequestHeaders().getFirst(UserServiceClient.TOKEN_HEADER));
        seenBodies.add(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        String path = ex.getRequestURI().getPath();
        String query = ex.getRequestURI().getRawQuery();
        int status = 200;
        String body;
        if (path.equals("/internal/users/lookup") && "username=alice".equals(query)) {
            body = ALICE;
        } else if (path.equals("/internal/users/lookup")) {
            status = 404; body = "";
        } else if (path.endsWith("/verify-password")) {
            body = seenBodies.getLast().contains("\"right\"") ? "{\"valid\":true}" : "{\"valid\":false}";
        } else if (path.equals("/internal/users/search")) {
            body = "[" + ALICE + "]";
        } else if (path.equals("/internal/users/count")) {
            body = "{\"count\":42}";
        } else if (path.equals("/internal/users/boom")) {
            status = 500; body = "oops";
        } else {
            status = 404; body = "";
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) ex.getResponseBody().write(bytes);
        ex.close();
    }

    @Test
    void mapsUserAndSendsToken() {
        RemoteUser alice = client.findByUsername("alice").orElseThrow();
        assertEquals("alice@example.com", alice.email());
        assertEquals(List.of("user"), alice.roles());
        assertTrue(alice.enabled());
        assertEquals("s3cret", seenTokens.getFirst());
    }

    @Test
    void notFoundIsEmpty() {
        assertTrue(client.findByUsername("nobody").isEmpty());
        assertTrue(client.findById("unknown").isEmpty());
    }

    @Test
    void verifiesPassword() {
        assertTrue(client.verifyPassword("id", "right"));
        assertFalse(client.verifyPassword("id", "wrong"));
    }

    @Test
    void searchAndCount() {
        assertEquals(1, client.search("ali", 0, 10).size());
        assertEquals(42, client.count(""));
    }

    @Test
    void serverErrorThrowsInsteadOfPretendingUserMissing() {
        assertThrows(UserServiceClient.UserServiceException.class, () -> client.findById("boom"));
    }

    @Test
    void unreachableThrows() {
        UserServiceClient dead = new UserServiceClient(HttpClient.newHttpClient(),
                "http://127.0.0.1:1", "x", Duration.ofMillis(500));
        assertThrows(UserServiceClient.UserServiceException.class, () -> dead.findByUsername("alice"));
    }

    @Test
    void adminConsoleSearchParamsAreNormalised() {
        assertEquals("", UserServiceStorageProvider.query(Map.of(UserModel.SEARCH, "*")));
        assertEquals("ali", UserServiceStorageProvider.query(Map.of(UserModel.SEARCH, "*ali*")));
        assertEquals("bob", UserServiceStorageProvider.query(Map.of(UserModel.SEARCH, "\"bob\"")));
        assertEquals("x@y", UserServiceStorageProvider.query(Map.of(UserModel.EMAIL, "x@y")));
        assertEquals("", UserServiceStorageProvider.query(Map.of()));
    }
}
