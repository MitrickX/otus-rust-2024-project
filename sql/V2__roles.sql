DO $$ BEGIN
    CREATE TYPE permission AS ENUM ('modify_ip_list', 'reset_rate_limiter', 'manage_role');
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