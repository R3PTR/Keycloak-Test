package com.example.userservice.web;

import java.time.Duration;
import java.util.Map;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.userservice.ApiException;
import com.example.userservice.AppProperties;
import com.example.userservice.keycloak.KeycloakClient;
import com.example.userservice.keycloak.KeycloakClient.TokenResponse;
import com.example.userservice.user.UserDtos.RegisterRequest;
import com.example.userservice.user.UserDtos.UserView;
import com.example.userservice.user.UserService;

/**
 * Login/logout via Keycloak, on the server side.
 *
 * <p>Token handling: the <b>access token</b> is returned in the body (the SPA keeps it
 * in memory and sends it as Bearer to /api and /users/me). The <b>refresh token</b>
 * never reaches JavaScript: it's an HttpOnly, SameSite=Strict cookie scoped to /users.
 *
 * <p>CSRF: refresh/logout act on that cookie, so they also require the
 * {@code X-Requested-With} header. A cross-site form can't set it, and a
 * cross-origin fetch would need a CORS preflight that this service never approves.
 */
@RestController
@RequestMapping("/users")
class AuthController {

    static final String REFRESH_COOKIE = "refresh_token";
    static final String CSRF_HEADER = "X-Requested-With";

    record LoginRequest(@NotBlank @Size(max = 255) String username, @NotBlank @Size(max = 128) String password) {
    }

    record LoginResponse(String accessToken, long expiresIn, String tokenType) {
    }

    private final KeycloakClient keycloak;
    private final UserService users;
    private final boolean secureCookie;

    AuthController(KeycloakClient keycloak, UserService users, AppProperties props) {
        this.keycloak = keycloak;
        this.users = users;
        this.secureCookie = props.cookieSecure();
    }

    @PostMapping("/login")
    ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest req) {
        TokenResponse tokens = keycloak.passwordGrant(req.username().strip(), req.password());
        return withTokens(tokens);
    }

    @PostMapping("/refresh")
    ResponseEntity<?> refresh(@CookieValue(name = REFRESH_COOKIE, required = false) String refreshToken,
                                          @RequestHeader(name = CSRF_HEADER, required = false) String csrf) {
        requireCsrfHeader(csrf);
        if (refreshToken == null || refreshToken.isBlank()) {
            return sessionExpired();
        }
        try {
            return withTokens(keycloak.refresh(refreshToken));
        } catch (ApiException e) {
            if (e.status() == HttpStatus.UNAUTHORIZED) {
                return sessionExpired();
            }
            throw e;
        }
    }

    @PostMapping("/logout")
    ResponseEntity<Void> logout(@CookieValue(name = REFRESH_COOKIE, required = false) String refreshToken,
                                @RequestHeader(name = CSRF_HEADER, required = false) String csrf) {
        requireCsrfHeader(csrf);
        if (refreshToken != null && !refreshToken.isBlank()) {
            keycloak.logout(refreshToken);
        }
        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, clearedCookie()).build();
    }

    @PostMapping("/register")
    ResponseEntity<UserView> register(@Valid @RequestBody RegisterRequest req) {
        return ResponseEntity.status(HttpStatus.CREATED).body(UserView.of(users.register(req)));
    }

    // ------------------------------------------------------------------------

    private ResponseEntity<LoginResponse> withTokens(TokenResponse t) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE, t.refreshToken())
                .httpOnly(true).secure(secureCookie).sameSite("Strict").path("/users")
                .maxAge(Duration.ofSeconds(t.refreshExpiresInOr(1800)))
                .build();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(new LoginResponse(t.accessToken(), t.expiresInOr(300), "Bearer"));
    }

    private String clearedCookie() {
        return ResponseCookie.from(REFRESH_COOKIE, "")
                .httpOnly(true).secure(secureCookie).sameSite("Strict").path("/users").maxAge(0).build().toString();
    }

    private static void requireCsrfHeader(String value) {
        if (value == null || value.isBlank()) {
            throw ApiException.forbidden("csrf", "Missing " + CSRF_HEADER + " header");
        }
    }

    private ResponseEntity<Map<String, String>> sessionExpired() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.SET_COOKIE, clearedCookie())
                .body(Map.of("error", "session_expired", "message", "Please sign in"));
    }
}
