create table users (
    id             uuid         primary key,
    username       varchar(32)  not null,
    email          varchar(255) not null,
    first_name     varchar(100) not null,
    last_name      varchar(100) not null,
    password_hash  varchar(100) not null,
    enabled        boolean      not null default true,
    email_verified boolean      not null default false,
    created_at     timestamptz  not null,
    updated_at     timestamptz  not null,
    version        bigint       not null default 0,
    -- The application stores both lower-cased; the checks make that a guarantee.
    constraint users_username_lower check (username = lower(username)),
    constraint users_email_lower    check (email = lower(email))
);

create unique index users_username_uq on users (username);
create unique index users_email_uq    on users (email);

create table user_roles (
    user_id uuid        not null references users (id) on delete cascade,
    role    varchar(64) not null,
    primary key (user_id, role)
);
