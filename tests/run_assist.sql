DELETE FROM sgw_keystore WHERE key_type != 'ROOT_KEY';
DELETE FROM as_keystore WHERE key_type != 'ROOT_KEY';
DELETE FROM gs_s_keystore;
DELETE FROM gs_t_keystore;



select id,key_type,key_state,owner1,owner2,key_cipher from sgw_keystore;
select id,key_type,key_state,owner1,owner2,key_cipher from as_keystore;
select id,key_type,key_state,owner1,owner2,key_cipher from gs_s_keystore;
select id,key_type,key_state,owner1,owner2,key_cipher from gs_t_keystore;
select id,key_type,key_state,owner1,owner2,key_cipher from gs_t2_keystore;



 DELETE from as_keystore;
 DELETE FROM gs_keystore;
 DELETE FROM sgw_keystore;