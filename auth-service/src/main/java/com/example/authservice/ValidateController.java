package com.example.authservice;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * Target of nginx {@code auth_request}. Only reached once the JWT has been fully
 * validated by Spring Security; this controller performs the optional role check
 * and returns identity headers that nginx forwards to the upstream.
 *
 * <p>nginx only looks at the status code: 2xx = allow, 401/403 = deny.
 */
@RestController
public class ValidateController {

    private static final Logger log = LoggerFactory.getLogger(ValidateController.class);

    @GetMapping("/validate")
    public ResponseEntity<Void> validate(
            @AuthenticationPrincipal Jwt jwt,
            @RequestHeader(name = "X-Required-Role", required = false) String requiredRole,
            @RequestHeader(name = "X-Original-URI", required = false) String originalUri) {

        List<String> roles = realmRoles(jwt);

        if (requiredRole != null && !requiredRole.isBlank() && !roles.contains(requiredRole)) {
            log.info("Denied {} to sub={}: missing role '{}'", originalUri, jwt.getSubject(), requiredRole);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        return ResponseEntity.ok()
                .header("X-User-Id", jwt.getSubject())
                .header("X-User-Name", headerSafe(jwt.getClaimAsString("preferred_username")))
                .header("X-User-Email", headerSafe(jwt.getClaimAsString("email")))
                .header("X-User-Roles", String.join(",", roles))
                .build();
    }

    /** Keycloak puts realm roles at {@code realm_access.roles}. */
    static List<String> realmRoles(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess == null || !(realmAccess.get("roles") instanceof Collection<?> roles)) {
            return List.of();
        }
        return roles.stream().filter(Objects::nonNull).map(Object::toString).map(ValidateController::headerSafe).toList();
    }

    /** Prevent header injection / non-ASCII issues from claim values. */
    private static String headerSafe(String value) {
        if (value == null) {
            return "";
        }
        return value.replaceAll("[^\\x20-\\x7E]", "").replace(",", "");
    }
}
