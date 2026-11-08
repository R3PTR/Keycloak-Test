package com.example.keycloak.userstorage;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.UserCredentialManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapter;

/**
 * Read-only view of a user-service user. All setters inherited from
 * {@link AbstractUserAdapter} throw {@code ReadOnlyException}: users are
 * managed through the user-service API, not the Keycloak admin console.
 */
class UserServiceUserAdapter extends AbstractUserAdapter {

    private static final Logger LOG = Logger.getLogger(UserServiceUserAdapter.class);

    private final RemoteUser user;

    UserServiceUserAdapter(KeycloakSession session, RealmModel realm, ComponentModel model, RemoteUser user) {
        super(session, realm, model);
        this.user = user;
        // Keycloak id = "f:<componentId>:<user-service UUID>" (default would use the username).
        this.storageId = new StorageId(StorageId.keycloakId(model, user.id()));
        this.created = user.createdAt();
    }

    RemoteUser remote() {
        return user;
    }

    /** Routes credential checks back to the provider's CredentialInputValidator. */
    @Override
    public SubjectCredentialManager credentialManager() {
        return new UserCredentialManager(session, realm, this);
    }

    // --- Required actions ---------------------------------------------------
    // Read-only users can't store required actions; the inherited methods throw.
    // Keycloak calls removeRequiredAction(VERIFY_PROFILE) after every successful
    // login (VerifyUserProfile trigger), which would turn each login into a 500.
    // Removing is a no-op (there is never anything stored); adding is ignored with
    // a warning because profile data is owned and validated by user-service.

    @Override
    public void removeRequiredAction(String action) {
        // nothing stored, nothing to remove
    }

    @Override
    public void removeRequiredAction(RequiredAction action) {
        // nothing stored, nothing to remove
    }

    @Override
    public void addRequiredAction(String action) {
        LOG.warnf("Ignoring required action %s for federated user %s (managed by user-service)",
                action, getUsername());
    }

    @Override
    public void addRequiredAction(RequiredAction action) {
        addRequiredAction(action.name());
    }

    @Override
    public String getUsername() {
        return user.username();
    }

    @Override
    public String getEmail() {
        return user.email();
    }

    @Override
    public boolean isEmailVerified() {
        return user.emailVerified();
    }

    @Override
    public String getFirstName() {
        return user.firstName();
    }

    @Override
    public String getLastName() {
        return user.lastName();
    }

    @Override
    public boolean isEnabled() {
        return user.enabled();
    }

    /**
     * Keycloak's user profile reads attributes from here. Without email/firstName/lastName
     * the default profile considers the account incomplete ("Account is not fully set up").
     */
    @Override
    public Map<String, List<String>> getAttributes() {
        MultivaluedHashMap<String, String> attributes = new MultivaluedHashMap<>();
        attributes.add(UserModel.USERNAME, user.username());
        putIfPresent(attributes, UserModel.EMAIL, user.email());
        putIfPresent(attributes, UserModel.FIRST_NAME, user.firstName());
        putIfPresent(attributes, UserModel.LAST_NAME, user.lastName());
        return attributes;
    }

    @Override
    public String getFirstAttribute(String name) {
        List<String> values = getAttributes().get(name);
        return values == null || values.isEmpty() ? null : values.getFirst();
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
        List<String> values = getAttributes().get(name);
        return values == null ? Stream.empty() : values.stream();
    }

    /** Maps user-service role names onto existing realm roles; unknown names are ignored. */
    @Override
    protected Set<RoleModel> getRoleMappingsInternal() {
        return user.roles().stream()
                .map(realm::getRole)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    private static void putIfPresent(MultivaluedHashMap<String, String> map, String key, String value) {
        if (value != null && !value.isBlank()) {
            map.add(key, value);
        }
    }
}
