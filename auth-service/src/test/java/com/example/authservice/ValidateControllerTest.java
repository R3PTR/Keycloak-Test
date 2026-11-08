package com.example.authservice;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class ValidateControllerTest {

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        TestKeys.register(registry);
    }

    @Autowired
    MockMvc mvc;

    private static final Map<String, Object> USER_ROLES = Map.of("roles", List.of("user"));
    private static final Map<String, Object> ADMIN_ROLES = Map.of("roles", List.of("user", "admin"));

    @Test
    void rejectsMissingToken() throws Exception {
        mvc.perform(get("/validate"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer realm=\"demo\""));
    }

    @Test
    void rejectsMalformedToken() throws Exception {
        mvc.perform(get("/validate").header("Authorization", "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer realm=\"demo\", error=\"invalid_token\""));
    }

    @Test
    void acceptsValidTokenAndReturnsIdentityHeaders() throws Exception {
        mvc.perform(get("/validate").with(jwt().jwt(j -> j
                        .subject("123")
                        .claim("preferred_username", "alice")
                        .claim("email", "alice@example.com")
                        .claim("realm_access", USER_ROLES))))
                .andExpect(status().isOk())
                .andExpect(header().string("X-User-Id", "123"))
                .andExpect(header().string("X-User-Name", "alice"))
                .andExpect(header().string("X-User-Email", "alice@example.com"))
                .andExpect(header().string("X-User-Roles", "user"));
    }

    @Test
    void forbidsWhenRequiredRoleMissing() throws Exception {
        mvc.perform(get("/validate").header("X-Required-Role", "admin")
                        .with(jwt().jwt(j -> j.claim("realm_access", USER_ROLES))))
                .andExpect(status().isForbidden());
    }

    @Test
    void allowsWhenRequiredRolePresent() throws Exception {
        mvc.perform(get("/validate").header("X-Required-Role", "admin")
                        .with(jwt().jwt(j -> j.claim("realm_access", ADMIN_ROLES))))
                .andExpect(status().isOk())
                .andExpect(header().string("X-User-Roles", "user,admin"));
    }

    @Test
    void healthIsPublic() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }
}
