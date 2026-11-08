package com.example.userservice.user;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Request/response shapes. Password hashes never appear in any of them. */
public final class UserDtos {

    private UserDtos() {
    }

    public static final String USERNAME_REGEX = "^[a-zA-Z0-9._-]{3,32}$";

    public record RegisterRequest(
            @NotBlank @Pattern(regexp = USERNAME_REGEX,
                    message = "3-32 characters: letters, digits, '.', '_' or '-'") String username,
            @NotBlank @Email @Size(max = 255) String email,
            @NotBlank @Size(max = 100) String firstName,
            @NotBlank @Size(max = 100) String lastName,
            @NotBlank @Size(min = 8, max = 128) String password) {
    }

    public record UpdateProfileRequest(
            @NotBlank @Email @Size(max = 255) String email,
            @NotBlank @Size(max = 100) String firstName,
            @NotBlank @Size(max = 100) String lastName) {
    }

    public record ChangePasswordRequest(
            @NotBlank String currentPassword,
            @NotBlank @Size(min = 8, max = 128) String newPassword) {
    }

    /** Admin patch: null fields are left unchanged. */
    public record AdminUpdateRequest(Boolean enabled, Set<String> roles) {
    }

    /** Public/admin view. */
    public record UserView(UUID id, String username, String email, String firstName, String lastName,
                           boolean enabled, boolean emailVerified, List<String> roles,
                           Instant createdAt, Instant updatedAt) {

        public static UserView of(UserEntity u) {
            return new UserView(u.getId(), u.getUsername(), u.getEmail(), u.getFirstName(), u.getLastName(),
                    u.isEnabled(), u.isEmailVerified(), u.getRoles().stream().sorted().toList(),
                    u.getCreatedAt(), u.getUpdatedAt());
        }
    }

    /** Shape consumed by the Keycloak SPI ({@code RemoteUser}); createdAt in epoch millis. */
    public record InternalUser(String id, String username, String email, String firstName, String lastName,
                               boolean enabled, boolean emailVerified, List<String> roles, long createdAt) {

        public static InternalUser of(UserEntity u) {
            return new InternalUser(u.getId().toString(), u.getUsername(), u.getEmail(), u.getFirstName(),
                    u.getLastName(), u.isEnabled(), u.isEmailVerified(), u.getRoles().stream().sorted().toList(),
                    u.getCreatedAt().toEpochMilli());
        }
    }

    public record PageView<T>(List<T> content, long total, int page, int size) {
    }
}
