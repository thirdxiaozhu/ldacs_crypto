/**
 * 20240514 by wencheng
 * 根密钥预置完成后，密钥建立过程样例：AS GS SGW的密钥生成和分发
 */
#include <stdio.h>
#include <string.h>
#include "key_manage.h"
#include "kmdb.h"
#include <uuid/uuid.h>

static km_field_desc km_fields[] = {
    // 密钥结构体字段描述
    {ft_uuid, 0, "id", NULL},
    {ft_enum, 0, "key_type", NULL},
    {ft_uint8t_pointer, 0, "owner1", NULL},
    {ft_uint8t_pointer, 0, "owner2", NULL},
    {ft_uint8t_pointer, 0, "key_cipher", NULL},
    {ft_uint32t, 0, "key_len", NULL},
    {ft_enum, 0, "key_state", NULL},
    {ft_timet, 128, "creatime", NULL},
    {ft_uint16t, 0, "updatecycle", NULL},
    {ft_uint32t, 0, "kek_len", NULL},
    {ft_uint8t_pointer, 0, "kek_cipher", NULL},
    {ft_uint8t_pointer, 0, "iv", NULL},
    {ft_uint16t, 0, "iv_len", NULL},
    {ft_enum, 0, "chck_algo", NULL},
    {ft_uint16t, 0, "check_len", NULL},
    {ft_uint8t_pointer, 0, "chck_value", NULL},
    {ft_uint16t, 0, "update_count", NULL},
    {ft_end, 0, NULL, NULL},
};

struct_desc static test_km_desc = {"km_pkg", km_fields};

int main()
{

    int ret;
    uint8_t *dbname = "keystore.db";
    uint8_t *as_tablename = "as_keystore";
    uint8_t *gs_tablename = "gs_s_keystore";
    uint8_t *sgw_tablename = "sgw_keystore";
    uint8_t *primary_key = "id";
    uint8_t *sac_sgw = "SGW"; // 测试本地标识
    uint8_t *sac_gs = "GS1";
    uint8_t *sac_as = "Berry";

    // 创建表
    create_table_if_not_exist(&test_km_desc, dbname, as_tablename, primary_key, NULL, NULL, FALSE);  // 根据描述创建表
    create_table_if_not_exist(&test_km_desc, dbname, gs_tablename, primary_key, NULL, NULL, FALSE);  // 根据描述创建表
    create_table_if_not_exist(&test_km_desc, dbname, sgw_tablename, primary_key, NULL, NULL, FALSE); // 根据描述创建表

    /**************************************************
     *                    SGW端                        *
     **************************************************/
    // 生成共享信息shareinfo
    uint32_t sharedinfo_len = 32;
    uint8_t sharedinfo[sharedinfo_len];
    ret = km_generate_random(sharedinfo, sharedinfo_len); // 用随机数填充
    if (ret != LD_KM_OK)
    {
        log_warn("[**sgw generate sharedinfo error**]\n");
        return 0;
    }

    // 获取根密钥
    void * handle_rootkey;
    QueryResult_for_queryid *rk_id = query_id(dbname, sgw_tablename, sac_as, sac_sgw, ROOT_KEY, ACTIVE);
    if (rk_id == NULL)
    {
        log_warn("NULL Query.\n");
        return 0;
    }

    ret = get_handle_from_db(dbname, sgw_tablename, rk_id->ids[0], &handle_rootkey);
    if (ret != LD_KM_OK)
    {
        log_warn("[**sgw get_rootkey_handle error**]\n");
        return 0;
    }

    // 派生主密钥：密钥KAS-SGW=KDF(rootkey,sharedinfo)派生
    void * handle_kassgw; // AS和SGW之间的主密钥
    struct KeyPkg *pkg_kassgw;  // 用于保存主密钥信息
    uint16_t len_kassgw = 16;   // 主密钥长度
    pkg_kassgw = km_derive_key(handle_rootkey, MASTER_KEY_AS_SGW, len_kassgw, sac_as, sac_sgw, sharedinfo, sharedinfo_len, &handle_kassgw);
    if (pkg_kassgw == NULL)
    {
        log_warn("[**sgw derive_key kas-sgw error**]\n");
        return 0;
    }
    else
    {
        log_warn("[**sgw derive_key KAS-SGW OK**]\n");
        // print_key_pkg(pkg_kassgw);
        store_key(dbname, sgw_tablename, pkg_kassgw, &test_km_desc); // SGW存储与AS之间的主密钥
    }

    // 省略：构造AUC_RESP消息 用KAS-SGW计算消息校验值

    /**************************************************
     *                    AS端                         *
     **************************************************/

    // 省略：和SGW同理 获取根密钥

    // 派生主密钥KAS-SGW
    km_keypkg_t *pkg_kassgw2;
    pkg_kassgw2 = km_derive_key(handle_rootkey, MASTER_KEY_AS_SGW, len_kassgw, sac_as, sac_sgw, sharedinfo, sharedinfo_len, &handle_kassgw);
    if (pkg_kassgw2 == NULL)
    {
        log_warn("[**AS derive_key kas-sgw error**]\n");
        return 0;
    }
    else
    {
        log_warn("[**AS derive_key KAS-SGW OK**]\n");
        store_key(dbname, as_tablename, pkg_kassgw2, &test_km_desc); // SGW存储与AS之间的主密钥
    }

    // 省略：密钥校验

    // 生成随机数N3,用于后续密钥派生
    uint16_t rand_len = 16;
    uint8_t rand[rand_len];
    ret = km_generate_random(rand, rand_len);
    if (ret != LD_KM_OK)
    {
        log_warn("[**AS generate_random N3 error**]\n");
        return 0;
    }

    // 省略：构造密钥确认消息 计算校验值

    // 主密钥KAS-GS派生
    uint16_t len_kasgs = 16;
    void * handle_kasgs;
    if (km_derive_masterkey_asgs(dbname, as_tablename, handle_kassgw, len_kasgs, sac_as, sac_gs, rand, rand_len, &handle_kasgs) != LD_KM_OK)
    {
        log_warn("[**AS derive master KAS-GS failed]\n");
        return 0;
    }
    log_warn("[**AS derive master KAS-GS OK]\n");

    // 会话密钥派生
    uint16_t len_session_key = 16;
    if (km_derive_all_session_key(dbname, as_tablename, handle_kasgs, len_session_key, sac_as, sac_gs, rand, rand_len) != LD_KM_OK)
    {
        log_warn("session key derive failed\n");
        return 0;
    }
    log_warn("[** AS derive session key OK]\n");

    /**************************************************
     *                    SGW端                        *
     **************************************************/

    // 省略：密钥校验
    // 密钥KAS-GS派生 和AS同理：NH = KDF(KAS-SGW,rand)
    void * handle_kasgs2;
    if (km_derive_masterkey_asgs(dbname, sgw_tablename, handle_kassgw, len_kasgs, sac_as, sac_gs, rand, rand_len, &handle_kasgs2) != LD_KM_OK)
    {
        log_warn("[**SGW derive master KAS-GS failed]\n");
        return 0;
    }
    log_warn("[**SGW derive_key KAS-GS OK  **]\n");

    // 查询新密钥id
    QueryResult_for_queryid *qr = query_id(dbname, sgw_tablename, sac_as, sac_gs, MASTER_KEY_AS_GS, ACTIVE);
    if (qr.count == 0)
    {
        log_warn("NULL Query.\n");
        return 0;
    }
    else if (qr.count > 1)
    {
        log_warn("query id not unique.\n");
        return 0;
    }

    // 查询密钥值
    QueryResult_for_keyvalue *result = query_keyvalue(dbname, sgw_tablename, qr.ids[0]);
    if (!result)
    {
        log_warn("Key not found or error occurred.\n");
        return 0;
    }

    // 省略：给GS分发KAS-GS rand rand_len
    log_warn("SGW sending kas-gs to GS.........\n");

    /**************************************************
     *                    GS端                        *
     **************************************************/

    // 安装密钥：安装主密钥并派生会话密钥
    if (km_install_key(dbname, gs_tablename, result.key_len, result.key, sac_as, sac_gs, rand_len, rand) != LD_KM_OK)
    {
        log_warn("km install key err\n");
        return 0;
    }
    log_warn("[**GS intstall key OK**]\n");

    return 0;
}