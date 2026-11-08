package com.example.userservice.user;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.stereotype.Component;

/** Seeds the demo users into an empty database (app.seed-demo-users=true). */
@Component
@ConditionalOnBooleanProperty("app.seed-demo-users")
class DemoUserSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoUserSeeder.class);

    private final UserRepository repo;
    private final UserService users;

    DemoUserSeeder(UserRepository repo, UserService users) {
        this.repo = repo;
        this.users = users;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (repo.count() > 0) {
            return;
        }
        // Passwords equal usernames for the demo; real users register via /users/register.
        users.create("alice", "alice@example.com", "Alice", "User", "alice", Set.of("user"));
        users.create("bob", "bob@example.com", "Bob", "Admin", "bob", Set.of("user", "admin"));
        repo.findAll().forEach(u -> {
            u.setEmailVerified(true);
            repo.save(u);
        });
        log.info("Seeded demo users alice/alice (user) and bob/bob (user, admin)");
    }
}
