package com.example.keycloak.userstorage;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;

/**
 * Registers the "user-service" provider (Admin console: User federation → user-service).
 */
public class UserServiceStorageProviderFactory implements UserStorageProviderFactory<UserServiceStorageProvider> {

    public static final String PROVIDER_ID = "user-service";

    static final String CONFIG_BASE_URL = "baseUrl";
    static final String CONFIG_API_TOKEN = "apiToken";
    static final String CONFIG_TIMEOUT_MS = "timeoutMs";

    private static final Logger log = Logger.getLogger(UserServiceStorageProviderFactory.class);

    /** Shared, thread-safe; connection pooling across requests. */
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .version(HttpClient.Version.HTTP_1_1)
            .build();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Users, passwords and roles stored in the user-service (Spring Boot + PostgreSQL).";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property().name(CONFIG_BASE_URL).label("User service URL")
                .helpText("Base URL of the user-service, e.g. http://user-service:8082")
                .type(ProviderConfigProperty.STRING_TYPE).defaultValue("http://user-service:8082").add()
                .property().name(CONFIG_API_TOKEN).label("Internal API token")
                .helpText("Shared secret sent as X-Internal-Token")
                .type(ProviderConfigProperty.PASSWORD).secret(true).add()
                .property().name(CONFIG_TIMEOUT_MS).label("Request timeout (ms)")
                .type(ProviderConfigProperty.STRING_TYPE).defaultValue("3000").add()
                .build();
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config)
            throws ComponentValidationException {
        String url = config.get(CONFIG_BASE_URL);
        if (url == null || url.isBlank()) {
            throw new ComponentValidationException("User service URL is required");
        }
        try {
            URI uri = URI.create(url);
            if (uri.getScheme() == null || !uri.getScheme().startsWith("http")) {
                throw new IllegalArgumentException();
            }
        } catch (IllegalArgumentException e) {
            throw new ComponentValidationException("User service URL must be an http(s) URL");
        }
        String token = config.get(CONFIG_API_TOKEN);
        if (token == null || token.isBlank()) {
            throw new ComponentValidationException("Internal API token is required");
        }
        timeout(config); // throws on garbage
    }

    @Override
    public UserServiceStorageProvider create(KeycloakSession session, ComponentModel model) {
        UserServiceClient client = new UserServiceClient(http, model.get(CONFIG_BASE_URL),
                model.get(CONFIG_API_TOKEN), timeout(model));
        return new UserServiceStorageProvider(session, model, client);
    }

    @Override
    public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {
        log.infof("User storage provider '%s' registered", PROVIDER_ID);
    }

    private static Duration timeout(ComponentModel model) {
        String raw = model.get(CONFIG_TIMEOUT_MS, "3000");
        try {
            return Duration.ofMillis(Long.parseLong(raw.trim()));
        } catch (NumberFormatException e) {
            throw new ComponentValidationException("Request timeout must be a number of milliseconds");
        }
    }
}
