package com.example.userservice.user;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.userservice.ApiException;
import com.example.userservice.user.UserDtos.AdminUpdateRequest;
import com.example.userservice.user.UserDtos.RegisterRequest;
import com.example.userservice.user.UserDtos.UpdateProfileRequest;

@Service
public class UserService {

    /** Roles that exist as realm roles in Keycloak (the SPI maps them by name). */
    public static final Set<String> ALLOWED_ROLES = Set.of("user", "admin");
    public static final String DEFAULT_ROLE = "user";

    private final UserRepository repo;
    private final PasswordEncoder encoder;
    /** Compared against when a user doesn't exist, so timing doesn't reveal it. */
    private final String dummyHash;

    public UserService(UserRepository repo, PasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
        this.dummyHash = encoder.encode("dummy-password-for-timing");
    }

    // --- registration / lookup ----------------------------------------------

    @Transactional
    public UserEntity register(RegisterRequest req) {
        return create(req.username(), req.email(), req.firstName(), req.lastName(), req.password(),
                Set.of(DEFAULT_ROLE));
    }

    @Transactional
    public UserEntity create(String username, String email, String firstName, String lastName,
                             String password, Set<String> roles) {
        String u = normalize(username);
        String e = normalize(email);
        if (repo.existsByUsername(u)) {
            throw ApiException.conflict("username_taken", "Username is already taken");
        }
        if (repo.existsByEmail(e)) {
            throw ApiException.conflict("email_taken", "Email is already registered");
        }
        UserEntity user = new UserEntity(u, e, firstName.strip(), lastName.strip(), encoder.encode(password));
        user.getRoles().addAll(validRoles(roles));
        try {
            return repo.saveAndFlush(user);
        } catch (DataIntegrityViolationException ex) {
            // Lost a race with a concurrent registration (unique index).
            throw ApiException.conflict("user_exists", "Username or email is already registered");
        }
    }

    @Transactional(readOnly = true)
    public UserEntity get(UUID id) {
        return repo.findById(id).orElseThrow(ApiException::notFound);
    }

    @Transactional(readOnly = true)
    public Optional<UserEntity> findById(UUID id) {
        return repo.findById(id);
    }

    @Transactional(readOnly = true)
    public Optional<UserEntity> findByUsername(String username) {
        return repo.findByUsername(normalize(username));
    }

    @Transactional(readOnly = true)
    public Optional<UserEntity> findByEmail(String email) {
        return repo.findByEmail(normalize(email));
    }

    @Transactional(readOnly = true)
    public Page<UserEntity> search(String query, int page, int size) {
        String q = normalize(query);
        return repo.search(q, likePattern(q), PageRequest.of(Math.max(page, 0), Math.clamp(size, 1, 100)));
    }

    @Transactional(readOnly = true)
    public List<UserEntity> searchSlice(String query, int first, int max) {
        String q = normalize(query);
        return repo.searchSlice(q, likePattern(q), Math.max(first, 0), Math.clamp(max, 1, 500));
    }

    @Transactional(readOnly = true)
    public long count(String query) {
        String q = normalize(query);
        return repo.countSearch(q, likePattern(q));
    }

    // --- credentials --------------------------------------------------------

    /** Used by Keycloak (via the SPI) to validate a login. */
    @Transactional(readOnly = true)
    public boolean verifyPassword(UUID id, String rawPassword) {
        Optional<UserEntity> user = repo.findById(id);
        String hash = user.map(UserEntity::getPasswordHash).orElse(dummyHash);
        boolean matches = encoder.matches(rawPassword, hash);
        return user.isPresent() && matches;
    }

    @Transactional
    public void changePassword(UUID id, String currentPassword, String newPassword) {
        UserEntity user = get(id);
        if (!encoder.matches(currentPassword, user.getPasswordHash())) {
            throw ApiException.badRequest("wrong_password", "Current password is incorrect");
        }
        if (encoder.matches(newPassword, user.getPasswordHash())) {
            throw ApiException.badRequest("same_password", "New password must differ from the current one");
        }
        user.setPasswordHash(encoder.encode(newPassword));
        user.touch();
    }

    // --- profile ------------------------------------------------------------

    @Transactional
    public UserEntity updateProfile(UUID id, UpdateProfileRequest req) {
        UserEntity user = get(id);
        String email = normalize(req.email());
        if (!email.equals(user.getEmail())) {
            if (repo.existsByEmail(email)) {
                throw ApiException.conflict("email_taken", "Email is already registered");
            }
            user.setEmail(email);
            user.setEmailVerified(false);
        }
        user.setFirstName(req.firstName().strip());
        user.setLastName(req.lastName().strip());
        user.touch();
        return user;
    }

    // --- admin --------------------------------------------------------------

    /**
     * @param actingAdmin id of the admin making the change; admins can't lock
     *                    themselves out (disable self or drop own admin role).
     */
    @Transactional
    public UserEntity adminUpdate(UUID id, AdminUpdateRequest req, UUID actingAdmin) {
        UserEntity user = get(id);
        boolean self = id.equals(actingAdmin);
        if (req.enabled() != null) {
            if (self && !req.enabled()) {
                throw ApiException.badRequest("self_lockout", "You cannot disable your own account");
            }
            user.setEnabled(req.enabled());
        }
        if (req.roles() != null) {
            Set<String> roles = validRoles(req.roles());
            if (self && !roles.contains("admin")) {
                throw ApiException.badRequest("self_lockout", "You cannot remove your own admin role");
            }
            user.getRoles().clear();
            user.getRoles().addAll(roles);
        }
        user.touch();
        return user;
    }

    @Transactional
    public void delete(UUID id, UUID actingAdmin) {
        if (id.equals(actingAdmin)) {
            throw ApiException.badRequest("self_lockout", "You cannot delete your own account here");
        }
        repo.delete(get(id));
    }

    // ------------------------------------------------------------------------

    static String normalize(String s) {
        return s == null ? "" : s.strip().toLowerCase(Locale.ROOT);
    }

    /** Case-insensitive "contains" with LIKE wildcards in user input escaped. */
    static String likePattern(String q) {
        String escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
        return "%" + escaped + "%";
    }

    private static Set<String> validRoles(Set<String> roles) {
        Set<String> normalized = new java.util.TreeSet<>();
        for (String r : roles) {
            String role = normalize(r);
            if (!ALLOWED_ROLES.contains(role)) {
                throw ApiException.badRequest("invalid_role", "Unknown role '" + r + "'. Allowed: " + ALLOWED_ROLES);
            }
            normalized.add(role);
        }
        if (normalized.isEmpty()) {
            throw ApiException.badRequest("invalid_role", "A user needs at least one role");
        }
        return normalized;
    }
}
