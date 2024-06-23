DO $$ BEGIN
    CREATE TYPE permission AS ENUM (
        'manage_role', 
        'manage_ip_list', 
        'view_ip_list',
        'reset_rate_limiter'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS roles (
    login TEXT NOT NULL,
    description TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    permissions permission[],
    PRIMARY KEY (login)
);

INSERT INTO roles (login, description, password_hash, permissions)
VALUES (
    'api-test-bot', 
    'Bot user for API testing',
    '$argon2id$v=19$m=19456,t=2,p=1$V9I9wGKkugNVkPGrDN4RmQ$VuGJDu4sautpFsbqla+6oBDjuGA7Ohi/nz/PITsc0MI', 
    ARRAY[
        'manage_role', 
        'manage_ip_list', 
        'view_ip_list',
        'reset_rate_limiter'
    ]::permission[]
);