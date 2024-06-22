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

INSERT INTO roles (login, description, password_hash, permissions)
VALUES (
    'api-test-bot', 
    'Bot user for API testing', 
    -- just random padding, not real password hash
    'BpgIICgpmBUkHF9fh2zZTB3FuhoWzTiY5LdS8HUUXSioSZx2lTdOgv99oNOJR1IXYcGOubxZVUUXSioSZx2lTdOgv99oNOJR1IXYcGOubTskRLByUTzJQ5mENd6siigZ', 
    ARRAY['modify_ip_list'::permission, 'reset_rate_limiter'::permission, 'manage_role'::permission],
);