package com.example.userservice.web;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.userservice.user.UserDtos.InternalUser;
import com.example.userservice.user.UserEntity;
import com.example.userservice.user.UserService;

/**
 * API for the Keycloak User Storage SPI. Protected by X-Internal-Token and not
 * routed by nginx. Mirrors exactly what the SPI's {@code UserServiceClient} calls.
 */
@RestController
@RequestMapping("/internal/users")
class InternalController {

    record VerifyPasswordRequest(String password) {
    }

    private final UserService users;

    InternalController(UserService users) {
        this.users = users;
    }

    @GetMapping("/{id}")
    ResponseEntity<InternalUser> byId(@PathVariable String id) {
        return respond(parseUuid(id).flatMap(users::findById));
    }

    @GetMapping("/lookup")
    ResponseEntity<InternalUser> lookup(@RequestParam(required = false) String username,
                                        @RequestParam(required = false) String email) {
        if (username != null) {
            return respond(users.findByUsername(username));
        }
        if (email != null) {
            return respond(users.findByEmail(email));
        }
        return ResponseEntity.badRequest().build();
    }

    @GetMapping("/search")
    List<InternalUser> search(@RequestParam(defaultValue = "") String q,
                              @RequestParam(defaultValue = "0") int first,
                              @RequestParam(defaultValue = "100") int max) {
        return users.searchSlice(q, first, max).stream().map(InternalUser::of).toList();
    }

    @GetMapping("/count")
    Map<String, Long> count(@RequestParam(defaultValue = "") String q) {
        return Map.of("count", users.count(q));
    }

    @PostMapping("/{id}/verify-password")
    ResponseEntity<Map<String, Boolean>> verifyPassword(@PathVariable String id,
                                                        @RequestBody VerifyPasswordRequest req) {
        Optional<UUID> uuid = parseUuid(id);
        if (uuid.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        boolean valid = req.password() != null && users.verifyPassword(uuid.get(), req.password());
        return ResponseEntity.ok(Map.of("valid", valid));
    }

    private static ResponseEntity<InternalUser> respond(Optional<UserEntity> user) {
        return user.map(InternalUser::of).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    private static Optional<UUID> parseUuid(String id) {
        try {
            return Optional.of(UUID.fromString(id));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
