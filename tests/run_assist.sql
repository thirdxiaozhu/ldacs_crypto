DELETE FROM sgw_keystore WHERE key_type != 'ROOT_KEY';
DELETE FROM as_keystore WHERE key_type != 'ROOT_KEY';

 select * from sgw_keystore;
 select * from as_keystore;

 DELETE from as_keystore;
 DELETE FROM gs_keystore;
 DELETE FROM sgw_keystore;