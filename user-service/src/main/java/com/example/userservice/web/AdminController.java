package com.example.userservice.web;

import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.userservice.ApiException;
import com.example.userservice.AppProperties;
import com.example.userservice.keycloak.KeycloakClient;
import com.example.userservice.user.UserDtos.AdminUpdateRequest;
import com.example.userservice.user.UserDtos.PageView;
import com.example.userservice.user.UserDtos.UserView;
import com.example.userservice.user.UserEntity;
import com.example.userservice.user.UserService;

/** User management. nginx requires realm role "admin"; the filter re-checks. */
@RestController
@RequestMapping("/users/admin/users")
class AdminController {

    private final UserService users;
    private final KeycloakClient keycloak;
    private final String componentId;

    AdminController(UserService users, KeycloakClient keycloak, AppProperties props) {
        this.users = users;
        this.keycloak = keycloak;
        this.componentId = props.keycloak().federationComponentId();
    }

    @GetMapping
    PageView<UserView> list(@RequestParam(defaultValue = "") String q,
                            @RequestParam(defaultValue = "0") int page,
                            @RequestParam(defaultValue = "20") int size) {
        Page<UserEntity> result = users.search(q, page, size);
        return new PageView<>(result.map(UserView::of).getContent(), result.getTotalElements(),
                result.getNumber(), result.getSize());
    }

    @GetMapping("/{id}")
    UserView get(@PathVariable UUID id) {
        return UserView.of(users.get(id));
    }

    /**
     * Enable/disable and set roles. Sessions are ended afterwards so the change
     * takes effect now (disabled → can't refresh; roles → new tokens carry them).
     */
    @PatchMapping("/{id}")
    UserView update(@RequestAttribute(GatewayUser.ATTRIBUTE) GatewayUser gw,
                    @PathVariable UUID id, @RequestBody AdminUpdateRequest req) {
        UserView updated = UserView.of(users.adminUpdate(id, req, actingAdmin(gw)));
        try {
            keycloak.logoutAllSessions(id);
        } catch (ApiException e) {
            throw new ApiException(e.status(), "sessions_not_ended",
                    "Change saved, but the user's sessions could not be ended");
        }
        return updated;
    }

    @PostMapping("/{id}/logout")
    ResponseEntity<Void> logout(@PathVariable UUID id) {
        users.get(id); // 404 if unknown
        keycloak.logoutAllSessions(id);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{id}")
    ResponseEntity<Void> delete(@RequestAttribute(GatewayUser.ATTRIBUTE) GatewayUser gw, @PathVariable UUID id) {
        keycloak.logoutAllSessions(id);
        users.delete(id, actingAdmin(gw));
        return ResponseEntity.noContent().build();
    }

    /** Null if the admin isn't a federated user (e.g. a Keycloak-local admin). */
    private UUID actingAdmin(GatewayUser gw) {
        return gw.userId(componentId).orElse(null);
    }
}
