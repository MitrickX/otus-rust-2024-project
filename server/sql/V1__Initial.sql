CREATE TABLE IF NOT EXISTS ip_list (
    ip BIT VARYING (128) NOT NULL,
    mask BIT VARYING (128) NULL,
    ip_str VARCHAR (64) NOT NULL,
    network_length SMALLINT NULL,
    is_v6 BOOLEAN NOT NULL,
    kind VARCHAR(32) NOT NULL,
    PRIMARY KEY (ip_str, kind)
);

CREATE UNIQUE INDEX ip_mask ON ip_list USING btree (ip, mask, kind);
CREATE INDEX mask ON ip_list USING btree (mask);
CREATE INDEX kind ON ip_list USING btree (kind);