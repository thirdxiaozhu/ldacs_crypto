// 查找
select id, owner1, owner2, key_type, key_state from as_keystore;
select id, owner1, owner2, key_type, key_state from gs_s_keystore;
select id, owner1, owner2, key_type, key_state from gs_t_keystore;
select id, owner1, owner2, key_type, key_state from sgw_keystore;


select id from test_key where owner1 ='Berry' and owner2='GS1';
(会话密钥查找 key_type LIKE '%SESSIONS%')
select owner1, owner2, key_type, key_state from test_key where key_type LIKE '%SESSION%' and key_state = 'ACTIVE';

// 删除
drop table as_keystore;
drop table gs_s_keystore;
drop table gs_t_keystore;
drop table sgw_keystore;

DELETE FROM as_keystore;
DELETE FROM gs_s_keystore;
DELETE FROM gs_t_keystore;
DELETE FROM sgw_keystore;

// 修改
UPDATE as_keystore SET key_state = 'ACTIVE' WHERE key_type = 'MASTER_KEY_AS_GS';
DELETE FROM as_keystore where owner2 = 'GSt';
UPDATE your_table
UPDATE gs_s_keystore SET key_state = 'ACTIVE';