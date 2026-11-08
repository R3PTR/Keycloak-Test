package com.example.backend;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.jayway.jsonpath.JsonPath;

@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class ApiControllerTest {

    @Autowired
    MockMvc mvc;

    private static MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder req, String id, String roles) {
        return req.header("X-User-Id", id).header("X-User-Name", id + "-name").header("X-User-Roles", roles);
    }

    @Test
    void rejectsRequestsWithoutGatewayIdentity() throws Exception {
        mvc.perform(get("/api/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void meReflectsGatewayHeaders() throws Exception {
        mvc.perform(as(get("/api/me"), "u1", "user, admin"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("u1"))
                .andExpect(jsonPath("$.roles", hasSize(2)));
    }

    @Test
    void notesAreIsolatedPerUser() throws Exception {
        mvc.perform(as(post("/api/notes"), "u1", "user")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"text\":\"hello\"}"))
                .andExpect(status().isCreated());

        mvc.perform(as(get("/api/notes"), "u1", "user")).andExpect(jsonPath("$", hasSize(1)));
        mvc.perform(as(get("/api/notes"), "u2", "user")).andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    void cannotDeleteSomeoneElsesNote() throws Exception {
        String body = mvc.perform(as(post("/api/notes"), "u1", "user")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"text\":\"mine\"}"))
                .andReturn().getResponse().getContentAsString();
        String id = JsonPath.read(body, "$.id");

        mvc.perform(as(delete("/api/notes/" + id), "u2", "user")).andExpect(status().isNotFound());
        mvc.perform(as(delete("/api/notes/" + id), "u1", "user")).andExpect(status().isNoContent());
    }

    @Test
    void rejectsBlankNote() throws Exception {
        mvc.perform(as(post("/api/notes"), "u1", "user")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"text\":\"  \"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void adminEndpointsRequireAdminRole() throws Exception {
        mvc.perform(as(get("/api/admin/notes"), "u1", "user")).andExpect(status().isForbidden());
        mvc.perform(as(get("/api/admin/notes"), "u1", "user,admin"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalNotes").value(0));
    }
}
