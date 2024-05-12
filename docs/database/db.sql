// 数据表结构
CREATE TABLE KeyPkg (
    id TEXT PRIMARY KEY,
    owner_1 TEXT,
    owner_2 TEXT,
    key_type INTEGER,
    length INTEGER,
    state INTEGER,
    creation_time INTEGER,
    update_cycle INTEGER,
    kek_cipher BLOB,
    kek_cipher_len INTEGER,
    key_cipher BLOB,
    iv_len INTEGER,
    iv BLOB,
    chck_len INTEGER,
    chck_alg INTEGER,
    chck_value BLOB
);