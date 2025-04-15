//
// Created by wencheng on 4/15/25.
//

#include "../include/kmdb.h"

// 将文件存入密码卡文件区 指定输入文件的路径 存入密码卡时的文件名
l_km_err km_writefile_to_cryptocard(const char *filepath, const char *filename) {
    void *DeviceHandle, *hSessionHandle;
    FILE *file;
    uint32_t file_size;
    uint16_t result;
    uint8_t *buffer = NULL; // 初始化指针为 NULL

    // 打开设备
    if (SDF_OpenDevice(&DeviceHandle) != SDR_OK) {
        fprintf(stderr, "Error opening device.\n");
        return LD_ERR_KM_OPEN_DEVICE;
    }

    // 打开会话句柄
    if (SDF_OpenSession(DeviceHandle, &hSessionHandle) != SDR_OK) {
        fprintf(stderr, "Error opening session.\n");
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_SESSION;
    }

    // 打开文件
    file = fopen(filepath, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error opening file %s.\n", filepath);
        SDF_CloseSession(hSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_OPEN_FILE;
    }

    // 定位文件末尾以获取文件大小
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    rewind(file);

    // 分配内存以存储文件内容
    buffer = (uint8_t *) malloc(file_size * sizeof(uint8_t));
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation error.\n");
        fclose(file);
        SDF_CloseSession(hSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_WRITE_FILE;
    }

    // 将文件内容读入缓冲区
    result = fread(buffer, sizeof(uint8_t), file_size, file);
    if (result != file_size) {
        fprintf(stderr, "Error reading file.\n");
        fclose(file);
        free(buffer); // 确保释放分配的内存
        SDF_CloseSession(hSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_WRITE_FILE;
    }

    // 文件内容写入密码卡
    int writeFileResult = SDF_WriteFile(hSessionHandle, filename, strlen((char *) filename), 0, file_size, buffer);
    if (writeFileResult != SDR_OK) {
        fprintf(stderr, "Error writing to cryptocard file %s, return %08x\n", filename, writeFileResult);
        fclose(file);
        free(buffer); // 确保释放分配的内存
        SDF_CloseSession(hSessionHandle);
        SDF_CloseDevice(DeviceHandle);
        return LD_ERR_KM_WRITE_FILE;
    }

    // 关闭文件
    fclose(file);
    // 释放内存
    free(buffer);
    // 关闭会话和设备
    SDF_CloseSession(hSessionHandle);
    SDF_CloseDevice(DeviceHandle);

    return LD_KM_OK;
}

static void usage() {
    printf("piico-import usage:\n"
           "\t piico-import [local-rootkey-path] [filename-in-cryptocard]\n"
           "Exit...\n"
    );
}

int main(int argc, const char **argv) {
    if (argc < 2 || argc > 3) {
        usage();
        exit(0);
    }
    const char *filepath = argv[1];
    const char *card_keyname = argv[2];

    if (km_writefile_to_cryptocard(filepath, card_keyname) != LD_KM_OK) {
        printf("Import failed\n");
        exit(0);
    }
    printf("Finished\n");
    return 0;
}