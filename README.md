# Keycloak + nginx `auth_request` + user-service (User Storage SPI)

```
client ──► nginx :8080 ─┬─ /               ──► frontend SPA (static)
                        ├─ /users/login|register|refresh|logout ──► user-service (public, rate limited)
                        ├─ /users/me/*    ──► user-service   auth_request /_auth/
                        ├─ /users/admin/* ──► user-service   auth_request /_auth/admin
                        ├─ /auth/*        ──► Keycloak (Postgres-backed)
                        ├─ /public/*      ──► backend (no auth)
                        ├─ /api/*         ──► backend   ┐ auth_request /_auth/
                        └─ /api/admin/*   ──► backend   ┘ auth_request /_auth/admin
                                                │
                                   auth-service:8081/validate (Spring Boot)
                                   verifies RS256 signature with realm public key, exp/nbf, iss, aud, typ,
                                   optional realm role → 200 / 401 / 403 + X-User-* headers

Login:  SPA ─POST /users/login─► user-service ─password grant─► Keycloak
                                     ▲                              │ User Storage SPI
                                     └── /internal/users/... ◄──────┘ (lookup, verify-password)
                                    users-db (PostgreSQL): users, BCrypt hashes, roles
```

## Components

| Service        | Purpose |
|----------------|---------|
| `postgres`     | Keycloak database (sessions, realm config; **no** application users) |
| `users-db`     | user-service database: users, BCrypt password hashes, roles (Flyway migrations) |
| `user-service` | Spring Boot: login/refresh/logout, registration, profile, password change, user admin; internal API for the SPI |
| `keycloak-spi` | Keycloak User Storage provider. Federates users from user-service (built into the Keycloak image) |
| `keycloak`     | IdP, served under `/auth`, realm `demo` imported from `keycloak/realm-demo.json` |
| `auth-service` | Spring Boot 4 resource server; `GET /validate` is the `auth_request` target |
| `backend`      | Spring Boot notes API; trusts the `X-User-*` headers from nginx and never sees the JWT |
| `frontend`     | Plain HTML/JS SPA (no build step), served by nginx, own sign-in/registration forms against user-service |
| `nginx`        | Single entry point; enforces auth, injects `X-User-Id/Name/Email/Roles` |

## Run

```bash
docker compose up -d --build --wait
# Port 8080 taken? (e.g. by another container)
HTTP_PORT=8088 PUBLIC_URL=http://localhost:8088 docker compose up -d --build --wait
```

`PUBLIC_URL` must be the URL clients use. It sets the token `iss` claim and is what the auth service validates against.

Admin console: `$PUBLIC_URL/admin` (redirects to `/auth/admin/`, login admin / admin).

After editing `nginx/nginx.conf`: `docker compose restart nginx`.

## User service + Keycloak SPI

**Where users live.** Users live in user-service's PostgreSQL, not in Keycloak. The realm has a *User federation*
component (`user-service`, cache policy `NO_CACHE`) backed by `keycloak-spi`. Keycloak's ids for these users are
`f:<componentId>:<uuid>`, and that's the `sub` claim / `X-User-Id`. Users show up in the Keycloak admin console
(via search), read-only.

**SPI → user-service** (`/internal/users/**`, shared secret `X-Internal-Token`, not routed by nginx):

| Call | Used for |
|---|---|
| `GET /internal/users/{id}`, `GET /internal/users/lookup?username=` / `?email=` | user lookup |
| `POST /internal/users/{id}/verify-password` | password check (BCrypt stays in user-service) |
| `GET /internal/users/search?q=&first=&max=`, `GET /internal/users/count?q=` | admin console user list |

Roles are user-service role names (`user`, `admin`), mapped onto realm roles of the same name, so tokens carry
them in `realm_access.roles`. Gateway role checks work unchanged.

**Public API** (via nginx):

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /users/login` `{username,password}` | none (rate limited) | Password grant with the confidential client `user-service`. Returns `{accessToken, expiresIn}`. The refresh token is an `HttpOnly; SameSite=Strict; Path=/users` cookie |
| `POST /users/refresh` | cookie + `X-Requested-With` | New access token, rotates the cookie |
| `POST /users/logout` | cookie + `X-Requested-With` | Ends the Keycloak session, clears the cookie |
| `POST /users/register` | none (rate limited) | Creates the user with role `user` |
| `GET/PUT /users/me` | token | Profile (email, first/last name) |
| `PUT /users/me/password` | token | Needs the current password; **ends all sessions** |
| `POST /users/me/logout-all` | token | Sign out everywhere |
| `GET /users/admin/users?q=&page=&size=` | token + `admin` | Search/list |
| `PATCH /users/admin/users/{id}` `{enabled?, roles?}` | token + `admin` | Ends that user's sessions. Admins can't lock themselves out |
| `POST /users/admin/users/{id}/logout`, `DELETE /users/admin/users/{id}` | token + `admin` | |

**Security notes**
* Login failures always return the same `401 invalid_credentials` (wrong password, unknown user, disabled or locked
  account). Keycloak brute-force detection locks an account for 60 s after 5 failures, and nginx limits
  `/users/login|register` to 10/min per IP.
* The password grant bypasses Keycloak's login page, so there's no MFA, SSO or social login on this path. That was the
  chosen trade-off (own login form). `demo-client` (public, PKCE) still exists if you want Keycloak's own login page.
* user-service ends sessions through the Keycloak Admin API with its service account (`realm-management:
  manage-users`). Keycloak 26.8 requires the `kc-admin-api` scope for Admin API tokens. It's an *optional* scope on
  `user-service`, requested only in the `client_credentials` grant, so user tokens never carry Admin API audience.
* Secrets: `USER_SERVICE_INTERNAL_TOKEN` and `USER_SERVICE_CLIENT_SECRET` (see `.env.example`). The realm file uses
  `${...}` placeholders that Keycloak substitutes from its environment at import.

**Realm changes need a re-import:** `--import-realm` skips existing realms. To apply `realm-demo.json` changes,
reset Keycloak's database (application users in `users-db` are unaffected):
```bash
docker compose stop keycloak postgres && docker compose rm -f keycloak postgres
docker volume rm keycloak-gateway_postgres-data
docker compose up -d --build --wait && docker compose restart auth-service   # new realm key
```

## Demo app

Open **http://localhost:8080/** and sign in as `alice/alice` or `bob/bob` (seeded into `users-db`), or create
an account. Signed in, you get notes, profile and password change, and for admins user administration (grant/revoke
admin, enable/disable, sign out, delete).

* **My notes:** `GET/POST/DELETE /api/notes`, with notes kept per user (in memory, so they are lost on restart).
* **Who the backend thinks I am:** `GET /api/me`, showing the identity nginx passed to the backend.
* **Admin:** `GET /api/admin/notes` returns 403 for alice and every user's notes for bob.
* **Access token:** the decoded claims and an expiry countdown. The SPA keeps it in memory and refreshes it through
  `/users/refresh` (cookie) 30 s before expiry. A page reload restores the session the same way.
* **Gateway playground:** sends requests without a token or with a tampered one, so you can watch the 401s/403s in the request log.

Backend API:

| Method & path | Gateway rule |
|---|---|
| `GET /public/info` | none |
| `GET /api/me` | valid token |
| `GET/POST /api/notes`, `DELETE /api/notes/{id}` | valid token (own notes only) |
| `GET /api/admin/notes`, `DELETE /api/admin/notes/{id}` | token with role `admin` (backend re-checks) |

## Try it with curl

```bash
B=http://localhost:8080
TOKEN=$(curl -s -c /tmp/jar -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice"}' $B/users/login | jq -r .accessToken)

curl -s -H "Authorization: Bearer $TOKEN" $B/users/me   # profile from users-db
curl -i $B/api/hello                                   # 401
curl -i -H "Authorization: Bearer $TOKEN" $B/api/hello # 200, backend sees X-User-*
curl -i -H "Authorization: Bearer $TOKEN" $B/api/admin/x # 403 (alice isn't admin; use bob/bob)
```

Users: `alice/alice` (role `user`) and `bob/bob` (roles `user`, `admin`).
Refresh / logout use the cookie jar: `curl -b /tmp/jar -c /tmp/jar -H 'X-Requested-With: x' -X POST $B/users/refresh`.

## How it works

* **Signature: Keycloak's realm public key.** The auth service verifies RS256 signatures
  against the realm's RSA public key (other algorithms, including `none` and HS256, are rejected).
  The key comes from one of two places:
  1. **Pinned:** set `AUTH_PUBLIC_KEY` to the key from *Admin console → Realm settings → Keys →
     RS256 → Public key*. Keycloak's bare base64 and PEM both work.
  2. **Fetched (default):** if `AUTH_PUBLIC_KEY` is empty, the key is read once at startup from
     `public_key` on the realm endpoint (`AUTH_REALM_URI`, over the Docker network).

  The service logs a fingerprint at startup (`Verifying JWTs with RSA public key from … sha256 …`),
  so you can confirm which key is in use. The key is loaded only once, so after **rotating the realm
  key**, restart `auth-service` or update `AUTH_PUBLIC_KEY`. Until then, every token returns 401.
  A pinned key also stops matching if the Keycloak database is recreated (`docker compose down -v`
  generates a new realm key).
* **Claims.** `iss` must equal `AUTH_ISSUER_URI` (the public URL), `aud` must contain
  `demo-api` (added by an audience mapper on `demo-client`), `exp`/`nbf` are checked with a
  30 s skew, and `typ` must be `Bearer`. ID tokens and refresh tokens are therefore rejected.
* **Roles.** To protect a location with a role, use `auth_request /_auth/<role>;`. The auth
  service checks `realm_access.roles`.
* **Header trust.** nginx always overwrites `X-User-*` on protected routes and blanks them on
  public routes, so clients can't spoof them. The backend should only be reachable through nginx.
* **Caching.** nginx caches `200` auth decisions for 10 s, keyed on token + role. This
  means a token can still be accepted for up to 10 s after it expires or is revoked. Tune
  `proxy_cache_valid` or remove `proxy_cache` in `nginx/nginx.conf`.
  The cache is on disk and survives `docker compose restart nginx`. When you're testing key
  or config changes, wait 10 s or call the auth service directly.

## Production notes

* Terminate TLS at nginx and set `PUBLIC_URL=https://...`. Change all default passwords (`.env`).
* `directAccessGrantsEnabled` (password grant) is only enabled for demo/CLI testing. Turn
  it off and use authorization code + PKCE.
* Redirect URIs in `realm-demo.json` are `http://localhost:8080/*`. Adjust them for your host.
* `--import-realm` only imports if the realm doesn't exist. Run `docker compose down -v` to re-import.

## Dev

```bash
mvn test                        # both Spring modules (root aggregator pom)
docker compose up -d --build backend auth-service   # after Java changes
```

Frontend and nginx files are bind-mounted. Frontend edits only need a browser reload. nginx edits need
`docker compose restart nginx`.
