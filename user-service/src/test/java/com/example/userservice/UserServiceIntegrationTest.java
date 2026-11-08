package com.example.userservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import jakarta.servlet.http.Cookie;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import com.example.userservice.keycloak.KeycloakClient;
import com.example.userservice.keycloak.KeycloakClient.TokenResponse;
import com.example.userservice.user.UserService;
import com.jayway.jsonpath.JsonPath;

@SpringBootTest(properties = {
        "app.internal-token=test-internal-token",
        "app.seed-demo-users=true",
        "app.keycloak.federation-component-id=comp-1",
})
@AutoConfigureMockMvc
@Testcontainers
class UserServiceIntegrationTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres = new PostgreSQLContainer("postgres:17-alpine");

    @Autowired
    MockMvc mvc;

    @Autowired
    UserService users;

    @MockitoBean
    KeycloakClient keycloak;

    // --- helpers -------------------------------------------------------------

    private static String unique(String prefix) {
        return prefix + UUID.randomUUID().toString().substring(0, 8);
    }

    private UUID register(String username) throws Exception {
        String body = mvc.perform(post("/users/register").contentType(MediaType.APPLICATION_JSON).content("""
                        {"username":"%s","email":"%s@example.com","firstName":"Test","lastName":"User","password":"password123"}
                        """.formatted(username, username)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return UUID.fromString(JsonPath.read(body, "$.id"));
    }

    private static MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder req, UUID id, String roles) {
        return req.header("X-User-Id", "f:comp-1:" + id).header("X-User-Name", "x").header("X-User-Roles", roles);
    }

    private ResultActions internal(MockHttpServletRequestBuilder req) throws Exception {
        return mvc.perform(req.header("X-Internal-Token", "test-internal-token"));
    }

    // --- registration --------------------------------------------------------

    @Test
    void registerValidatesAndRejectsDuplicatesCaseInsensitively() throws Exception {
        String name = unique("reg");
        register(name);

        mvc.perform(post("/users/register").contentType(MediaType.APPLICATION_JSON).content("""
                        {"username":"%s","email":"other-%s@example.com","firstName":"A","lastName":"B","password":"password123"}
                        """.formatted(name.toUpperCase(), name)))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error").value("username_taken"));

        mvc.perform(post("/users/register").contentType(MediaType.APPLICATION_JSON).content("""
                        {"username":"%s","email":"%s@EXAMPLE.com","firstName":"A","lastName":"B","password":"password123"}
                        """.formatted(unique("x"), name)))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error").value("email_taken"));

        mvc.perform(post("/users/register").contentType(MediaType.APPLICATION_JSON).content("""
                        {"username":"a b","email":"nope","firstName":"","lastName":"B","password":"short"}"""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fields.username").exists())
                .andExpect(jsonPath("$.fields.email").exists())
                .andExpect(jsonPath("$.fields.password").exists());
    }

    @Test
    void registeredUserGetsDefaultRoleAndNoHashInResponse() throws Exception {
        mvc.perform(post("/users/register").contentType(MediaType.APPLICATION_JSON).content("""
                        {"username":"%s","email":"%s@example.com","firstName":"A","lastName":"B","password":"password123"}
                        """.formatted(unique("r"), unique("r"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.roles[0]").value("user"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andExpect(content -> assertThat(content.getResponse().getContentAsString()).doesNotContain("$2a$"));
    }

    // --- login / refresh / logout -------------------------------------------

    @Test
    void loginReturnsAccessTokenAndRefreshCookie() throws Exception {
        when(keycloak.passwordGrant("alice", "alice"))
                .thenReturn(new TokenResponse("ACCESS", 300L, "REFRESH", 1800L, "Bearer"));

        mvc.perform(post("/users/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("ACCESS"))
                .andExpect(jsonPath("$.expiresIn").value(300))
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andExpect(cookie().value("refresh_token", "REFRESH"))
                .andExpect(cookie().httpOnly("refresh_token", true))
                .andExpect(cookie().path("refresh_token", "/users"))
                .andExpect(header().string("Set-Cookie", containsString("SameSite=Strict")))
                .andExpect(header().string("Cache-Control", "no-store"));
    }

    @Test
    void loginFailureIsGeneric() throws Exception {
        when(keycloak.passwordGrant(anyString(), anyString()))
                .thenThrow(ApiException.unauthorized("invalid_credentials", "Invalid username or password"));

        mvc.perform(post("/users/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"nope\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_credentials"));
    }

    @Test
    void refreshNeedsCsrfHeaderAndRotatesCookie() throws Exception {
        when(keycloak.refresh("OLD")).thenReturn(new TokenResponse("ACCESS2", 300L, "NEW", 1800L, "Bearer"));

        mvc.perform(post("/users/refresh").cookie(new Cookie("refresh_token", "OLD")))
                .andExpect(status().isForbidden());
        verify(keycloak, never()).refresh(anyString());

        mvc.perform(post("/users/refresh").cookie(new Cookie("refresh_token", "OLD")).header("X-Requested-With", "fetch"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("ACCESS2"))
                .andExpect(cookie().value("refresh_token", "NEW"));

        mvc.perform(post("/users/refresh").header("X-Requested-With", "fetch"))
                .andExpect(status().isUnauthorized())
                .andExpect(cookie().maxAge("refresh_token", 0));
    }

    @Test
    void logoutEndsKeycloakSessionAndClearsCookie() throws Exception {
        mvc.perform(post("/users/logout").cookie(new Cookie("refresh_token", "R")).header("X-Requested-With", "fetch"))
                .andExpect(status().isNoContent())
                .andExpect(cookie().maxAge("refresh_token", 0));
        verify(keycloak).logout("R");
    }

    // --- internal API (Keycloak SPI) ----------------------------------------

    @Test
    void internalApiRequiresToken() throws Exception {
        mvc.perform(get("/internal/users/lookup").param("username", "alice")).andExpect(status().isUnauthorized());
        mvc.perform(get("/internal/users/lookup").param("username", "alice").header("X-Internal-Token", "wrong"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void internalLookupMatchesSpiContract() throws Exception {
        internal(get("/internal/users/lookup").param("username", "ALICE"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.email").value("alice@example.com"))
                .andExpect(jsonPath("$.firstName").value("Alice"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.emailVerified").value(true))
                .andExpect(jsonPath("$.roles[0]").value("user"))
                .andExpect(jsonPath("$.createdAt").isNumber())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        internal(get("/internal/users/lookup").param("email", "Bob@Example.com"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.roles").value(hasItem("admin")));
        internal(get("/internal/users/lookup").param("username", "nobody")).andExpect(status().isNotFound());
        internal(get("/internal/users/not-a-uuid")).andExpect(status().isNotFound());
    }

    @Test
    void internalVerifyPassword() throws Exception {
        String id = JsonPath.read(internal(get("/internal/users/lookup").param("username", "alice"))
                .andReturn().getResponse().getContentAsString(), "$.id");

        internal(post("/internal/users/" + id + "/verify-password").contentType(MediaType.APPLICATION_JSON)
                .content("{\"password\":\"alice\"}")).andExpect(jsonPath("$.valid").value(true));
        internal(post("/internal/users/" + id + "/verify-password").contentType(MediaType.APPLICATION_JSON)
                .content("{\"password\":\"wrong\"}")).andExpect(jsonPath("$.valid").value(false));
        internal(post("/internal/users/" + UUID.randomUUID() + "/verify-password").contentType(MediaType.APPLICATION_JSON)
                .content("{\"password\":\"alice\"}")).andExpect(jsonPath("$.valid").value(false));
    }

    @Test
    void internalSearchEscapesWildcards() throws Exception {
        internal(get("/internal/users/search").param("q", "ali").param("first", "0").param("max", "10"))
                .andExpect(jsonPath("$[*].username").value(hasItem("alice")));
        internal(get("/internal/users/search").param("q", "%"))
                .andExpect(jsonPath("$.length()").value(0));
        internal(get("/internal/users/search").param("q", "").param("first", "0").param("max", "1"))
                .andExpect(jsonPath("$.length()").value(1));
        internal(get("/internal/users/count").param("q", "bob"))
                .andExpect(jsonPath("$.count").value(1));
    }

    // --- /users/me -----------------------------------------------------------

    @Test
    void meRequiresFederatedGatewayIdentity() throws Exception {
        mvc.perform(get("/users/me")).andExpect(status().isUnauthorized());
        mvc.perform(get("/users/me").header("X-User-Id", "some-local-keycloak-user"))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error").value("not_managed"));
    }

    @Test
    void profileUpdate() throws Exception {
        UUID id = register(unique("me"));
        mvc.perform(as(put("/users/me"), id, "user").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"NEW-" + id + "@example.com\",\"firstName\":\" Neo \",\"lastName\":\"Anderson\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("new-" + id + "@example.com"))
                .andExpect(jsonPath("$.firstName").value("Neo"))
                .andExpect(jsonPath("$.emailVerified").value(false));

        mvc.perform(as(put("/users/me"), id, "user").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"alice@example.com\",\"firstName\":\"x\",\"lastName\":\"y\"}"))
                .andExpect(status().isConflict());
    }

    @Test
    void changePasswordVerifiesCurrentAndEndsSessions() throws Exception {
        UUID id = register(unique("pw"));
        mvc.perform(as(put("/users/me/password"), id, "user").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"wrong-one\",\"newPassword\":\"brandnew123\"}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("wrong_password"));
        verify(keycloak, never()).logoutAllSessions(id);

        mvc.perform(as(put("/users/me/password"), id, "user").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"password123\",\"newPassword\":\"brandnew123\"}"))
                .andExpect(status().isNoContent());
        verify(keycloak).logoutAllSessions(id);
        assertThat(users.verifyPassword(id, "brandnew123")).isTrue();
        assertThat(users.verifyPassword(id, "password123")).isFalse();
    }

    // --- admin ---------------------------------------------------------------

    @Test
    void adminEndpointsRequireAdminRole() throws Exception {
        UUID id = register(unique("na"));
        mvc.perform(as(get("/users/admin/users"), id, "user")).andExpect(status().isForbidden());
    }

    @Test
    void adminCanDisableAndChangeRolesWhichEndsSessions() throws Exception {
        UUID admin = register(unique("adm"));
        UUID target = register(unique("tgt"));

        mvc.perform(as(patch("/users/admin/users/" + target), admin, "user,admin").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false,\"roles\":[\"user\",\"ADMIN\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.roles").value(hasItem("admin")));
        verify(keycloak).logoutAllSessions(target);

        mvc.perform(as(patch("/users/admin/users/" + target), admin, "user,admin").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[\"superuser\"]}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_role"));
    }

    @Test
    void adminCannotLockThemselvesOut() throws Exception {
        UUID admin = register(unique("self"));
        mvc.perform(as(patch("/users/admin/users/" + admin), admin, "user,admin").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\":false}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("self_lockout"));
        mvc.perform(as(patch("/users/admin/users/" + admin), admin, "user,admin").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"roles\":[\"user\"]}"))
                .andExpect(status().isBadRequest());
        mvc.perform(as(delete("/users/admin/users/" + admin), admin, "user,admin"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void adminListAndDelete() throws Exception {
        UUID admin = register(unique("lst"));
        String victimName = unique("del");
        UUID victim = register(victimName);

        mvc.perform(as(get("/users/admin/users").param("q", victimName), admin, "admin"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.content[0].username").value(victimName));

        mvc.perform(as(delete("/users/admin/users/" + victim), admin, "admin")).andExpect(status().isNoContent());
        verify(keycloak).logoutAllSessions(victim);
        internal(get("/internal/users/" + victim)).andExpect(status().isNotFound());
        mvc.perform(as(delete("/users/admin/users/" + victim), admin, "admin")).andExpect(status().isNotFound());
    }

    @Test
    void keycloakOutageSurfacesAs503NotAs401() throws Exception {
        when(keycloak.passwordGrant(eq("bob"), any()))
                .thenThrow(new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "keycloak_unavailable", "Login is currently unavailable"));
        mvc.perform(post("/users/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"bob\",\"password\":\"bob\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.error").value(not("invalid_credentials")));
    }
}
