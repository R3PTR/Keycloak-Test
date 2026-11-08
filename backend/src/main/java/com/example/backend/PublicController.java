package com.example.backend;

import java.time.Instant;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Unauthenticated endpoint (nginx /public/ has no auth_request). */
@RestController
class PublicController {

    @GetMapping({"/public", "/public/", "/public/info"})
    Map<String, Object> info() {
        return Map.of("message", "Public endpoint: no token required", "time", Instant.now().toString());
    }
}
