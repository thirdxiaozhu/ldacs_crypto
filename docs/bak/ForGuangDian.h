// 将密钥及其元数据做标准封装
// l_km_err generate_keypkg(struct KeyMetaData *key_info, uint8_t *cipher_key, uint8_t *iv_for_mac, unsigned int iv_len, void *mac_key_handle, struct KeyPkg *key_pkg);

// 导入KEK （仅光电密码卡支持）
// l_km_err import_kek(unsigned int key_index, void *key_cipher, unsigned int key_len);

// 生成KEK （仅光电密码卡支持）
// l_km_err generate_kek(unsigned int key_bits_len, unsigned int key_index);

// 导出KEK （仅光电密码卡支持）
// l_km_err export_kek(unsigned int key_index, void *key_cipher, unsigned int *key_len);

// sm3 hmac （仅光电密码卡支持 ）
// l_km_err sm3_hmac(uint8_t *key_cipher, uint32_t key_len, uint8_t *data, uint32_t data_len,
//                uint8_t *hmac_data, uint32_t *hmac_data_len);

/* 光电+光电密码卡方案：因为AS不支持PCIE 此方案不适用

// 打印kek包 （仅光电密码卡支持）
// l_km_err print_kek_pkg(struct KEKPkg *kek_pkg);

// 将kek写入文件
l_km_err write_kekpkg_to_file(const char *filename, struct KEKPkg *pkg);

// 将kek从文件中读出并清除文件内容
l_km_err read_kdkpkg_from_file(const char *filename, struct KEKPkg *pkg);

// 生成并导出KEK
l_km_err generate_and_export_kek(int key_len, int kek_index, uint8_t *rcver, int rcver_len, struct KEKPkg *kek_pkg);

// 验证并导入KEK到指定索引位置
l_km_err external_import_kek(struct KEKPkg *kek_pkg, int kek_index, uint8_t *local_id, int id_len);

// 光电+派科PICE转USB的接口 非对称方案 此方案不适用
void writePublicKeyToFile(ECCrefPublicKey *pk, const char *filename);

void readPublicKeyFromFile(ECCrefPublicKey *pk_as, const char *filename);

void writeCipherToFile(ECCCipher *rootkey, const char *filename);

void readCipherFromFile(ECCCipher *rootkey_from_as, const char *filename);

void printECCrefPublicKey(const ECCrefPublicKey *key_cipher);

void printECCCipher(const ECCCipher *cipher);

int compareECCCipher(const ECCCipher *cipher1, const ECCCipher *cipher2);

int compareECCrefPublicKey(const ECCrefPublicKey *key1, const ECCrefPublicKey *key2);


// 主密钥派生会话密钥 输入共享随机数 派生密钥类型，生成密钥返回句柄和描述信息key_info
l_km_err derive_session_key(
    void *master_key_handle,
    enum KEY_TYPE key_type,
    uint8_t *rand,
    uint32_t rand_len,
    void *session_key_handle,
    struct KeyMetaData *key_info);*/