#include <stdio.h>
#include <string.h>
/**
 * @author wencheng
 * @brief 预处理代码测试
 */
int main()
{
    FILE *fp;
    char hostname[50];

    // 获取主机名
    fp = popen("hostname", "r");
    fgets(hostname, sizeof(hostname), fp);
    log_warn("Hostname: %s\n", hostname);
    pclose(fp);

// 检查主机名是否包含特定字符串
// #ifdef SGW
    if (strstr(hostname, "gateway") != NULL)
    {
        log_warn("This is an SGW host.\n");
        // SGW 主机特定代码
    }
    else
    {
        log_warn("This is an SGW host, but in host name  gateway isn't included.\n");
    }
    /*
#elif AS
    if (strstr(hostname, "as") != NULL) {
        log_warn("This is an AS host.\n");
        // AS 主机特定代码
    }
#elif GS
    if (strstr(hostname, "gs") != NULL) {
        log_warn("This is a GS host.\n");
        // GS 主机特定代码
    }
#else
    log_warn("Unknown host type.\n");
#endif
#else
log_warn("This code is only for Linux.\n");
#endif
*/
    return 0;
}
