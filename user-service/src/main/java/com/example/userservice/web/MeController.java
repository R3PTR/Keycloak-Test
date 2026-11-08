package com.example.userservice.web;

import java.util.UUID;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.userservice.ApiException;
import com.example.userservice.AppProperties;
import com.example.userservice.keycloak.KeycloakClient;
import com.example.userservice.user.UserDtos.ChangePasswordRequest;
import com.example.userservice.user.UserDtos.UpdateProfileRequest;
import com.example.userservice.user.UserDtos.UserView;
import com.example.userservice.user.UserService;

/** The signed-in user's own account. Requires a valid token (nginx auth_request). */
@RestController
@RequestMapping("/users/me")
class MeController {

    private final UserService users;
    private final KeycloakClient keycloak;
    private final String componentId;

    MeController(UserService users, KeycloakClient keycloak, AppProperties props) {
        this.users = users;
        this.keycloak = keycloak;
        this.componentId = props.keycloak().federationComponentId();
    }

    @GetMapping
    UserView me(@RequestAttribute(GatewayUser.ATTRIBUTE) GatewayUser gw) {
        return UserView.of(users.get(id(gw)));
    }

    @PutMapping
    UserView update(@RequestAttribute(GatewayUser.ATTRIBUTE) GatewayUser gw,
                    @Valid @RequestBody UpdateProfileRequest req) {
        return UserView.of(users.updateProfile(id(gw), req));
    }

    /** Changes the password and signs out every session, including this one. */
    @PutMapping("/password")
    ResponseEntity<Void> changePassword(@RequestAttribute(GatewayUser.ATTRIBUTE) GatewayUser gw,
                                        @Valid @RequestBody ChangePasswordRequest req) {
        UUID id = id(gw);
        users.changePassword(id, req.currentPassword(), req.newPassword());
        endSessions(id, "Password changed, but existing sessions could not be signed out. Try 'Sign out everywhere'.");
        return ResponseEntity.noContent().build();
    }

    /** "Sign out everywhere". */
    @PostMapping("/logout-all")
    ResponseEntity<Void> logoutAll(@RequestAttribute(GatewayUser.ATTRIBUTE) GatewayUser gw) {
        keycloak.logoutAllSessions(id(gw));
        return ResponseEntity.noContent().build();
    }

    private void endSessions(UUID id, String messageIfFailed) {
        try {
            keycloak.logoutAllSessions(id);
        } catch (ApiException e) {
            throw new ApiException(e.status(), "sessions_not_ended", messageIfFailed);
        }
    }

    private UUID id(GatewayUser gw) {
        return gw.userId(componentId).orElseThrow(() ->
                ApiException.forbidden("not_managed", "This account is not managed by the user service"));
    }
}
