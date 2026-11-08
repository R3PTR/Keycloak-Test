package com.example.keycloak.userstorage;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Thin HTTP client for the user-service internal API ({@code /internal/users}).
 * Authenticates with a shared secret in {@code X-Internal-Token}.
 *
 * <p>404 means "no such user" ({@link Optional#empty()}). Every other failure
 * throws {@link UserServiceException}, so an outage surfaces as an error instead
 * of being mistaken for "user not found" or "wrong password".
 */
public class UserServiceClient {

    static final String TOKEN_HEADER = "X-Internal-Token";

    private static final ObjectMapper JSON = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private final HttpClient http;
    private final String baseUrl;
    private final String apiToken;
    private final Duration timeout;

    public UserServiceClient(HttpClient http, String baseUrl, String apiToken, Duration timeout) {
        this.http = http;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.apiToken = apiToken;
        this.timeout = timeout;
    }

    public Optional<RemoteUser> findById(String id) {
        return getOptional("/internal/users/" + enc(id), RemoteUser.class);
    }

    public Optional<RemoteUser> findByUsername(String username) {
        return getOptional("/internal/users/lookup?username=" + enc(username), RemoteUser.class);
    }

    public Optional<RemoteUser> findByEmail(String email) {
        return getOptional("/internal/users/lookup?email=" + enc(email), RemoteUser.class);
    }

    public List<RemoteUser> search(String query, int first, int max) {
        return get("/internal/users/search?q=" + enc(query) + "&first=" + first + "&max=" + max,
                new TypeReference<List<RemoteUser>>() { });
    }

    public int count(String query) {
        return get("/internal/users/count?q=" + enc(query), new TypeReference<Map<String, Integer>>() { })
                .getOrDefault("count", 0);
    }

    public boolean verifyPassword(String id, String password) {
        String body = write(Map.of("password", password));
        HttpResponse<String> res = send(request("/internal/users/" + enc(id) + "/verify-password")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build());
        if (res.statusCode() == 404) {
            return false;
        }
        expectOk(res);
        return read(res.body(), new TypeReference<Map<String, Boolean>>() { }).getOrDefault("valid", false);
    }

    // ---------------------------------------------------------------------

    private <T> Optional<T> getOptional(String path, Class<T> type) {
        HttpResponse<String> res = send(request(path).GET().build());
        if (res.statusCode() == 404) {
            return Optional.empty();
        }
        expectOk(res);
        try {
            return Optional.of(JSON.readValue(res.body(), type));
        } catch (IOException e) {
            throw new UserServiceException("Invalid JSON from user-service", e);
        }
    }

    private <T> T get(String path, TypeReference<T> type) {
        HttpResponse<String> res = send(request(path).GET().build());
        expectOk(res);
        return read(res.body(), type);
    }

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(timeout)
                .header(TOKEN_HEADER, apiToken)
                .header("Accept", "application/json");
    }

    private HttpResponse<String> send(HttpRequest req) {
        try {
            return http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new UserServiceException("user-service unreachable: " + req.method() + " " + req.uri().getPath(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new UserServiceException("Interrupted calling user-service", e);
        }
    }

    private static void expectOk(HttpResponse<String> res) {
        if (res.statusCode() / 100 != 2) {
            throw new UserServiceException("user-service returned HTTP " + res.statusCode()
                    + " for " + res.request().method() + " " + res.request().uri().getPath());
        }
    }

    private static <T> T read(String body, TypeReference<T> type) {
        try {
            return JSON.readValue(body, type);
        } catch (IOException e) {
            throw new UserServiceException("Invalid JSON from user-service", e);
        }
    }

    private static String write(Object value) {
        try {
            return JSON.writeValueAsString(value);
        } catch (IOException e) {
            throw new UserServiceException("Could not serialize request", e);
        }
    }

    private static String enc(String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }

    public static class UserServiceException extends RuntimeException {
        public UserServiceException(String message) {
            super(message);
        }

        public UserServiceException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
