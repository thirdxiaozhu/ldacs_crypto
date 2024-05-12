/*

// 国密hmac算法 （仅光电密码卡支持）
l_km_err sm3_hmac(uint8_t *key, uint32_t key_len, uint8_t *data, uint32_t data_len, uint8_t *hmac_data, uint32_t *hmac_data_len)
{
    // 在这里进行参数检查
    if (hmac_data == NULL)
    {
        printf("hmac_data has not been initalized\n");
        return LD_ERR_KM_PARAMETERS_NULL;
    }
    HANDLE DeviceHandle, hSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    // 调用已有接口 SDFE_Hmac
    ret = SDFE_Hmac(hSessionHandle, key, key_len, data, data_len, hmac_data, hmac_data_len);
    if (ret != LD_OK)
    {
        printf("SDFE_Hmac with phKeyHandle error!ret is %08x \n", ret);
        return LD_ERR_KM_SM3HMAC;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_OK;
}

// 将密钥及其元数据做标准封装 输出到密钥库文件中 校验算法chck_algo = ALGO_MAC
l_km_err generate_keypkg(struct KeyMetaData *key_info, uint8_t *cipher_key, uint8_t *iv_for_mac, unsigned int iv_len, void *mac_key_handle, struct KeyPkg *key_pkg)
{
    // 参数检查
    if (key_info == NULL)
    {
        printf("error: parameter key_info is null!\n");
        return LD_ERR_KM_PARAMETERS_NULL;
    }
    else if (cipher_key == NULL)
    {
        printf("error: parameter cipher_key is null!\n");
        return LD_ERR_KM_PARAMETERS_NULL;
    }
    else if (mac_key_handle == NULL)
    {
        printf("error: parameter mac_key_handle is null!\n");
        return LD_ERR_KM_PARAMETERS_NULL;
    }
    // 变量初始化分配空间
    if (key_pkg == NULL)
    {
        key_pkg = malloc(sizeof(struct KeyPkg));
    }

    // 计算密钥的校验值
    uint8_t mac_value[32];
    uint32_t mac_len;
    unsigned int chck_algo = ALGO_MAC;
    int ret = mac(mac_key_handle, chck_algo, iv_for_mac, cipher_key, key_info->length, mac_value, &mac_len);
    // printbuff("check value", mac_value, mac_len);

    // 生成标准封装格式密钥包
    key_pkg->meta_data = key_info;
    memcpy(key_pkg->key_cipher, cipher_key, key_info->length);
    key_pkg->chck_alg = chck_algo;
    memcpy(key_pkg->chck_value, mac_value, mac_len);
    key_pkg->chck_len = mac_len;
    memcpy(key_pkg->iv, iv_for_mac, mac_len);
    key_pkg->iv_len = iv_len;
    return LD_OK;
}

// 主密钥派生会话密钥 输入共享随机数 派生密钥类型，生成密钥返回句柄和描述信息key_info
l_km_err derive_session_key(void *master_key_handle, enum KEY_TYPE key_type, uint8_t *rand, uint32_t rand_len, void *session_key_handle, struct KeyMetaData *key_info)
{
    uint16_t key_len = 16; // 会话密钥长度默认为16字节
    uint8_t hash_value[32];
    uint8_t salt[32];
    uint32_t salt_len;
    uint8_t session_key[16];
    time_t current_time;
    int ret;

    // 检查输入参数是否为空
    if (rand == NULL || master_key_handle == NULL)
    {
        printf("LD_ERR_KM_PARAMETERS_NULL\n");
        return LD_ERR_KM_PARAMETERS_NULL;
    }
    // 初始化输入参数
    if (key_info == NULL)
    {
        key_info = (struct KeyMetaData *)malloc(sizeof(struct KeyMetaData));
    }

    // 初始化密钥元数据
    uuid_t uuid;
    // struct KeyMetaData *key_info = malloc(sizeof(struct KeyMetaData));
    uuid_generate(uuid);
    uuid_copy(key_info->id, uuid);
    key_info->key_type = key_type;
    key_info->length = key_len;
    key_info->state = PRE_ACTIVATION;
    key_info->creation_time = time(&current_time);
    key_info->update_cycle = 365; // 单位 天
    memset(key_info->owner_1, 0, sizeof(uint8_t) * MAX_OWENER_LEN);
    memset(key_info->owner_2, 0, sizeof(uint8_t) * MAX_OWENER_LEN);

    // key_info->counter = 0;

    // 派生密钥：rand作为password，使用主密钥对key_type加密的结果作为iv  输入pbkdf2后派生出密钥
    uint8_t *string_key_type = (uint8_t *)&key_type;
    ret = hash(SGD_SM3, string_key_type, sizeof(string_key_type), hash_value); // 计算key_type的hash值
    if (ret != LD_OK)
    {
        printf("LD_ERR_KM_DERIVE_SESSION_KEY\n");
        return LD_ERR_KM_DERIVE_SESSION_KEY;
    }

    // rand作为iv 使用主密钥对key_type的hash值加密，取前16byte作为盐值输入pbkdf2
    HANDLE DeviceHandle, hSessionHandle;
    SDF_OpenDevice(&DeviceHandle);                  // 打开设备
    SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    ret = SDF_Encrypt(hSessionHandle, master_key_handle, ALGO_ENC_AND_DEC, rand, hash_value, 32, salt, &salt_len);
    if (ret != LD_OK)
    {
        printf("LD_ERR_KM_DERIVE_SESSION_KEY\n");
        return LD_ERR_KM_DERIVE_SESSION_KEY;
    }
    SDF_CloseSession(hSessionHandle); // 关闭会话
    SDF_CloseDevice(DeviceHandle);    // 关闭设备

    salt_len = 16;                                                            // 取前16byte输入pbkdf
    ret = pbkdf2(rand, rand_len, salt, salt_len, 1024, key_len, session_key); // 使用SM3-HMAC作为密钥派生的PRF，迭代次数1024次。
    if (ret != LD_OK)
    {
        printf("LD_ERR_KM_DERIVE_SESSION_KEY\n");
        return LD_ERR_KM_DERIVE_SESSION_KEY;
    }

    // 打印密钥内容
    // switch (key_type)
    // {
    // case SESSION_KEY_USR_ENC:
    //     printbuff("Session Key For Encrytion", session_key, key_len);
    //     break;
    // case SESSION_KEY_USR_INT:
    //     printbuff("Session Key For Integrity", session_key, key_len);
    //     break;
    // default:
    //     printf("unknown key key_type\n");
    // }

    // 导入密钥 返回密钥句柄
    void *temp_handle;
    import_key(session_key, key_len, &temp_handle);
    // printf("session_key has been imported to pci-e crypto-card\n");

    // 销毁内存中的密钥
    // printf("session_key has been destructed in memory\n");

    // 拷贝密钥句柄
    memcpy(session_key_handle, temp_handle, sizeof(void *));
    // printf("Key as-sgw syccessfully derived!the Handle is %p\n", temp_handle);

    return LD_OK;
}


// 光电+光电密码卡方案：因为AS不支持PCIE 此方案不适用
// 将kekpkg写入文件：默认在build文件夹下
l_km_err write_kekpkg_to_file(const char *filename, struct KEKPkg *pkg)
{
    FILE *file = fopen(filename, "wb");
    if (file == NULL)
    {
        perror("Error opening file for writing");
        return LD_ERR_KM_WRITE_FILE;
        // exit(EXIT_FAILURE);
    }

    // 写入rcver_len
    fwrite(&pkg->rcver_len, sizeof(uint32_t), 1, file);
    // 写入rcver
    fwrite(pkg->rcver, sizeof(uint8_t), pkg->rcver_len, file);

    // 写入key_len
    fwrite(&pkg->key_len, sizeof(uint32_t), 1, file);
    // 写入key
    fwrite(pkg->key_cipher, sizeof(uint8_t), pkg->key_len, file);

    // 写入chck_len
    fwrite(&pkg->chck_len, sizeof(uint32_t), 1, file);
    // 写入chck_value
    fwrite(pkg->chck_value, sizeof(uint8_t), pkg->chck_len, file);

    fclose(file);
    return LD_OK;
}

// 从文件读取出kekpkg
l_km_err read_kdkpkg_from_file(const char *filename, struct KEKPkg *pkg)
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        perror("Error opening file for reading");
        return LD_ERR_KM_READ_FILE;
        // exit(EXIT_FAILURE);
    }

    // 读取rcver_len
    fread(&pkg->rcver_len, sizeof(uint32_t), 1, file);
    // 分配内存并读取rcver
    pkg->rcver = malloc(pkg->rcver_len * sizeof(uint8_t));
    fread(pkg->rcver, sizeof(uint8_t), pkg->rcver_len, file);

    // 读取key_len
    fread(&pkg->key_len, sizeof(uint32_t), 1, file);
    // 分配内存并读取key
    pkg->key_cipher = malloc(pkg->key_len * sizeof(uint8_t));
    fread(pkg->key_cipher, sizeof(uint8_t), pkg->key_len, file);

    // 读取chck_len
    fread(&pkg->chck_len, sizeof(uint32_t), 1, file);
    // 分配内存并读取chck_value
    pkg->chck_value = malloc(pkg->chck_len * sizeof(uint8_t));
    fread(pkg->chck_value, sizeof(uint8_t), pkg->chck_len, file);
    fclose(file);

    // 以写入方式打开文件，这将清空文件内容
    file = fopen(filename, "w");
    uint8_t *hint = "kek has been imported succesfully.";
    fwrite(hint, sizeof(uint8_t), strlen(hint), file);
    fclose(file);

    return LD_OK;
}

// 生成并导出KEK包
l_km_err generate_and_export_kek(int key_len, int kek_index, uint8_t *rcver, int rcver_len, struct KEKPkg *kek_pkg)
{
    HANDLE DeviceHandle, hSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    // 初始化结构体 分配空间
    kek_pkg->chck_value = (uint8_t *)malloc(32);
    kek_pkg->key_cipher = (uint8_t *)malloc(key_len / 16); // bit转字节
    kek_pkg->rcver = (uint8_t *)malloc(rcver_len);
    kek_pkg->rcver_len = rcver_len;
    memcpy(kek_pkg->rcver, rcver, rcver_len);

    int generate_ret = SDFE_GenerateKEK(hSessionHandle, key_len, kek_index);
    if (generate_ret != LD_OK)
    {
        printf("SDFE_GenerateKEK failed \n");
        return LD_ERR_KM_GENERATE_KEK;
    }

    int export_ret = SDFE_ExportKEK(hSessionHandle, kek_index, kek_pkg->key_cipher, &kek_pkg->key_len);
    if (export_ret != LD_OK)
    {
        printf("SDFE_ExportKEK failed \n");
        return LD_ERR_KM_EXPORT_KEK;
    }

    sm3_hmac(kek_pkg->key_cipher, kek_pkg->key_len, rcver, rcver_len, kek_pkg->chck_value, &kek_pkg->chck_len);
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_OK;
}

// 外部导入KEK：输入本地id验证kek 并导入KEK到指定索引位置
l_km_err external_import_kek(struct KEKPkg *kek_pkg, int kek_index, uint8_t *local_id, int id_len)
{
    HANDLE DeviceHandle, hSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }
    uint32_t local_chck_len;
    uint8_t local_chck_value[32];

    // verify kek
    if (memcmp(local_id, kek_pkg->rcver, id_len) != 0) // vefiry id
    {
        printf("this kek don't belong to me\n");
        return LD_ERR_KM_EXTERNAL_IMPORT_KEK;
    }
    else
    {
        printf("this kek belongs to me\n");
    }

    sm3_hmac(kek_pkg->key_cipher, kek_pkg->key_len, local_id, id_len, local_chck_value, &local_chck_len);
    // printbuff("pkg chck", kek_pkg->chck_value, kek_pkg->chck_len);
    // printbuff("local_chck", local_chck_value, local_chck_len);
    if (memcmp(local_chck_value, kek_pkg->chck_value, local_chck_len) != 0) // vefiry key_cipher
    {
        printf("this kek fail to pass hmac verify\n");
        return LD_ERR_KM_EXTERNAL_IMPORT_KEK;
    }
    else
    {
        printf("this kek has passed hmac verify\n");
    }

    // import kek
    int result = SDFE_ImportKEK(hSessionHandle, kek_index, kek_pkg->key_cipher, kek_pkg->key_len);
    if (result != LD_OK)
    {
        printf("kek has NOT been imported to index %d", kek_index);
        return LD_ERR_KM_EXTERNAL_IMPORT_KEK;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_OK;
}

// 光电+派科PICE转USB的接口 非对称方案 此方案不适用
void writePublicKeyToFile(ECCrefPublicKey *pk, const char *filename)
{
    FILE *file = fopen(filename, "wb"); // Open file in binary write mode
    if (file == NULL)
    {
        printf("Error opening file for writing.\n");
        return;
    }

    // Write the entire structure to the file
    fwrite(pk, sizeof(ECCrefPublicKey), 1, file);

    fclose(file);
}

void readPublicKeyFromFile(ECCrefPublicKey *pk_as, const char *filename)
{
    FILE *file = fopen(filename, "rb"); // Open file in binary read mode
    if (file == NULL)
    {
        printf("Error opening file for reading.\n");
        return;
    }

    // Read the entire structure from the file
    fread(pk_as, sizeof(ECCrefPublicKey), 1, file);

    fclose(file);
}

void writeCipherToFile(ECCCipher *rootkey, const char *filename)
{
    FILE *file = fopen(filename, "wb"); // Open file in binary write mode
    if (file == NULL)
    {
        printf("Error opening file for writing.\n");
        return;
    }

    // Write the entire structure to the file
    fwrite(rootkey, sizeof(ECCCipher), 1, file);

    fclose(file);
}

void readCipherFromFile(ECCCipher *rootkey, const char *filename)
{
    FILE *file = fopen(filename, "rb"); // Open file in binary read mode
    if (file == NULL)
    {
        printf("Error opening file for reading.\n");
        return;
    }

    // Read the entire structure from the file
    fread(rootkey, sizeof(ECCCipher), 1, file);

    fclose(file);
}

void printECCrefPublicKey(const ECCrefPublicKey *key_cipher)
{
    printf("ECCrefPublicKey:\n");
    printf("Bits: %u\n", key_cipher->bits);
    printf("x: ");
    for (int i = 0; i < ECCref_MAX_LEN; ++i)
    {
        printf("%02X ", key_cipher->x[i]);
    }
    printf("\n");
    printf("y: ");
    for (int i = 0; i < ECCref_MAX_LEN; ++i)
    {
        printf("%02X ", key_cipher->y[i]);
    }
    printf("\n");
}

void printECCCipher(const ECCCipher *cipher)
{
    printf("ECCCipher:\n");
    printf("x: ");
    for (int i = 0; i < ECCref_MAX_LEN; ++i)
    {
        printf("%02X ", cipher->x[i]);
    }
    printf("\n");
    printf("y: ");
    for (int i = 0; i < ECCref_MAX_LEN; ++i)
    {
        printf("%02X ", cipher->y[i]);
    }
    printf("\n");
    printf("M: ");
    for (int i = 0; i < 32; ++i)
    {
        printf("%02X ", cipher->M[i]);
    }
    printf("\n");
    printf("L: %u\n", cipher->L);
    printf("C: %02X\n", cipher->C[0]);
}

int compareECCCipher(const ECCCipher *cipher1, const ECCCipher *cipher2)
{
    // Compare each field of the structures
    if (memcmp(cipher1->x, cipher2->x, sizeof(cipher1->x)) != 0)
    {
        printf("x is different\n");
        return -1;
    }
    if (memcmp(cipher1->y, cipher2->y, sizeof(cipher1->y)) != 0)
    {
        printf("y is different\n");
        return 0;
    }
    if (memcmp(cipher1->M, cipher2->M, sizeof(cipher1->M)) != 0)
    {
        printf("m is different\n");
        return 0;
    }
    if (cipher1->L != cipher2->L)
    {
        printf("l is different\n");
        return 0;
    }
    if (memcmp(cipher1->C, cipher2->C, sizeof(cipher1->C)) != 0)
    {
        printf("c is different\n");
        return 0;
    }
    // If all fields are equal, return 1 (true)
    return 0;
}

int compareECCrefPublicKey(const ECCrefPublicKey *key1, const ECCrefPublicKey *key2)
{
    // Compare the 'bits' field
    if (key1->bits != key2->bits)
        return -1;

    // Compare the 'x' field
    if (memcmp(key1->x, key2->x, sizeof(key1->x)) != 0)
        return -1;

    // Compare the 'y' field
    if (memcmp(key1->y, key2->y, sizeof(key1->y)) != 0)
        return -1;

    // If all fields are equal, return 1 (true)
    return 0;
}

*/
/* 生成KEK (仅光电密码卡支持)
l_km_err generate_kek(unsigned int key_bits_len, unsigned int key_index)
{
    HANDLE DeviceHandle, hSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }
    int generate_ret = SDFE_GenerateKEK(hSessionHandle, key_bits_len, key_index);
    if (generate_ret != LD_OK)
    {
        printf("SDFE_GenerateKEK failed \n");
        return LD_ERR_KM_GENERATE_KEK;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_OK; ///////////////////////////////////////
}

// 导出KEK (仅光电密码卡支持)
l_km_err export_kek(unsigned int key_index, void *key, unsigned int *key_len)
{
    HANDLE DeviceHandle, hSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    int export_ret = SDFE_ExportKEK(hSessionHandle, key_index, key, key_len);
    if (export_ret != LD_OK)
    {
        printf("SDFE_ExportKEK failed \n");
        return LD_ERR_KM_EXPORT_KEK;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_OK;
}

// 导入KEK (仅光电密码卡支持)
l_km_err import_kek(unsigned int key_index, void *key, unsigned int key_len)
{
    HANDLE DeviceHandle, hSessionHandle;
    int ret;
    ret = SDF_OpenDevice(&DeviceHandle); // 打开设备
    if (ret != LD_OK)
    {
        printf("SDF_OpenDevice error!return 0x%08x\n", ret);
        return LD_ERR_KM_OPEN_DEVICE;
    }
    ret = SDF_OpenSession(DeviceHandle, &hSessionHandle); // 打开会话句柄
    if (ret != LD_OK)
    {
        printf("SDF_OpenSession error!return 0x%08x\n", ret);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    // import kek
    int result = SDFE_ImportKEK(hSessionHandle, key_index, key, key_len);
    if (result != LD_OK)
    {
        printf("kek has NOT been imported to index %d", key_index);
        return LD_ERR_KM_IMPORT_KEK;
    }

    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);
    return LD_OK;
}

*/
/*
// 展示kekpkg中的内容
l_km_err print_kek_pkg(struct KEKPkg *kek_pkg)
{
    if (kek_pkg == NULL)
    {
        // 输入指针为空，无法打印
        return LD_ERR_KM_PARAMETERS_NULL;
    }

    // 打印 rcver
    printf("reciever name: %s \n", kek_pkg->rcver);

    // 打印 key_len
    printf("Key Length: %u\n", kek_pkg->key_len);
    printbuff("Key", kek_pkg->key, kek_pkg->key_len);

    // 打印 chck_len
    printf("Check Length: %d\n", kek_pkg->chck_len);
    printbuff("Check Value", kek_pkg->chck_value, kek_pkg->chck_len);

    return LD_OK;
}
*/