package com.example.keycloak.userstorage;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;

/**
 * Federates users from user-service. One instance per Keycloak session (i.e. per
 * request), so the small lookup cache below never serves stale data across requests.
 */
public class UserServiceStorageProvider
        implements UserStorageProvider, UserLookupProvider, UserQueryProvider, CredentialInputValidator {

    private static final Logger log = Logger.getLogger(UserServiceStorageProvider.class);

    private final KeycloakSession session;
    private final ComponentModel model;
    private final UserServiceClient client;

    /** Per-request cache: Keycloak looks the same user up several times during one login. */
    private final Map<String, Optional<RemoteUser>> byId = new HashMap<>();
    private final Map<String, Optional<RemoteUser>> byUsername = new HashMap<>();

    public UserServiceStorageProvider(KeycloakSession session, ComponentModel model, UserServiceClient client) {
        this.session = session;
        this.model = model;
        this.client = client;
    }

    // --- UserLookupProvider ------------------------------------------------

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        String externalId = StorageId.externalId(id);
        return cached(byId, externalId, () -> client.findById(externalId))
                .map(u -> adapt(realm, u))
                .orElse(null);
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        return cached(byUsername, username.toLowerCase(), () -> client.findByUsername(username))
                .map(u -> adapt(realm, u))
                .orElse(null);
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        return client.findByEmail(email).map(this::remember).map(u -> adapt(realm, u)).orElse(null);
    }

    // --- CredentialInputValidator -------------------------------------------

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType()) || input.getChallengeResponse() == null) {
            return false;
        }
        String externalId = StorageId.externalId(user.getId());
        boolean valid = client.verifyPassword(externalId, input.getChallengeResponse());
        log.debugf("Password check for %s: %s", user.getUsername(), valid ? "valid" : "invalid");
        return valid;
    }

    // --- UserQueryProvider (admin console: Users list / search) -------------

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params,
                                                 Integer firstResult, Integer maxResults) {
        int first = firstResult == null || firstResult < 0 ? 0 : firstResult;
        int max = maxResults == null || maxResults < 0 ? 100 : maxResults;
        return client.search(query(params), first, max).stream()
                .map(this::remember)
                .map(u -> adapt(realm, u));
    }

    @Override
    public int getUsersCount(RealmModel realm, Map<String, String> params) {
        return client.count(query(params));
    }

    @Override
    public int getUsersCount(RealmModel realm) {
        return client.count("");
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer first, Integer max) {
        return Stream.empty(); // groups are not modelled in user-service
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        return switch (attrName) {
            case UserModel.USERNAME -> Stream.ofNullable(getUserByUsername(realm, attrValue));
            case UserModel.EMAIL -> Stream.ofNullable(getUserByEmail(realm, attrValue));
            default -> Stream.empty();
        };
    }

    @Override
    public void close() {
        // HttpClient is owned by the factory.
    }

    // ------------------------------------------------------------------------

    /**
     * Admin console sends either the free-text {@code search} param ("*" = all)
     * or field filters. user-service does one case-insensitive "contains" over
     * username, email, first and last name.
     */
    static String query(Map<String, String> params) {
        String q = params.get(UserModel.SEARCH);
        if (q == null) q = params.get(UserModel.USERNAME);
        if (q == null) q = params.get(UserModel.EMAIL);
        if (q == null) q = params.get(UserModel.FIRST_NAME);
        if (q == null) q = params.get(UserModel.LAST_NAME);
        if (q == null) return "";
        q = q.trim().replace("*", "");
        // Admin console wraps exact searches in quotes.
        if (q.length() >= 2 && q.startsWith("\"") && q.endsWith("\"")) q = q.substring(1, q.length() - 1);
        return q;
    }

    private UserModel adapt(RealmModel realm, RemoteUser user) {
        return new UserServiceUserAdapter(session, realm, model, user);
    }

    private RemoteUser remember(RemoteUser user) {
        byId.put(user.id(), Optional.of(user));
        byUsername.put(user.username().toLowerCase(), Optional.of(user));
        return user;
    }

    private Optional<RemoteUser> cached(Map<String, Optional<RemoteUser>> cache, String key,
                                        Supplier<Optional<RemoteUser>> loader) {
        Optional<RemoteUser> hit = cache.get(key);
        if (hit != null) {
            return hit;
        }
        Optional<RemoteUser> loaded = loader.get();
        loaded.ifPresentOrElse(this::remember, () -> cache.put(key, Optional.empty()));
        return loaded;
    }
}
