#include "util.h"
#include <iostream>

VOID PrintByteArray(_In_ PBYTE pByte, _In_ SIZE_T sSize) {
    for (size_t i = 0; i < sSize; i++) {
        if (i % 16 == 0 && i != 0 && i != sSize - 1) {
            printf("\\x%02x\"\n\t\"", pByte[i - 1]);
        }
        else if (i == 0 && i == sSize - 1) {
            printf("\t\"\\x%02x\";\n\n", pByte[i]);
        }
        else if (i == 0) {
            printf("\t\"\\x%02x", pByte[i]);
            i++;
        }
        else if (i + 1 == sSize) {
            printf("\\x%02x\";\n\n", pByte[i - 1]);
        }
        else {
            printf("\\x%02x", pByte[i - 1]);
        }
    }
}

BYTE *buffer_payload(wchar_t *filename, OUT size_t &r_size)
{
    HANDLE file = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if(file == INVALID_HANDLE_VALUE) {
        DEBUG_ERR("Could not open file!" << std::endl);
        return nullptr;
    }
    HANDLE mapping = CreateFileMapping(file, 0, PAGE_READONLY, 0, 0, 0);
    if (!mapping) {
        DEBUG_ERR("Could not create mapping!" << std::endl);
        CloseHandle(file);
        return nullptr;
    }
    BYTE *dllRawData = (BYTE*) MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (dllRawData == nullptr) {
        DEBUG_ERR("Could not map view of file" << std::endl);
        CloseHandle(mapping);
        CloseHandle(file);
        return nullptr;
    }
    r_size = GetFileSize(file, 0);
    BYTE* localCopyAddress = (BYTE*) VirtualAlloc(NULL, r_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (localCopyAddress == NULL) {
        DEBUG_ERR("Could not allocate memory in the current process" << std::endl);
        return nullptr;
    }
    memcpy(localCopyAddress, dllRawData, r_size);
    UnmapViewOfFile(dllRawData);
    CloseHandle(mapping);
    CloseHandle(file);
    return localCopyAddress;
}

void free_buffer(BYTE* buffer)
{
    if (buffer == NULL) return;
    VirtualFree(buffer, 0, MEM_RELEASE);
}

wchar_t* get_file_name(wchar_t *full_path)
{
    size_t len = wcslen(full_path);
    for (size_t i = len - 2; i >= 0; i--) {
        if (full_path[i] == '\\' || full_path[i] == '/') {
            return full_path + (i + 1);
        }
    }
    return full_path;
}

wchar_t* get_directory(IN wchar_t *full_path, OUT wchar_t *out_buf, IN const size_t out_buf_size)
{
    memset(out_buf, 0, out_buf_size);
    memcpy(out_buf, full_path, out_buf_size);

    wchar_t *name_ptr = get_file_name(out_buf);
    if (name_ptr != nullptr) {
        *name_ptr = '\0'; //cut it
    }
    return out_buf;
}

bool get_calc_path(LPWSTR lpwOutPath, DWORD szOutPath, bool isPayl32bit)
{
    if (isPayl32bit) {
#ifdef _WIN64
        ExpandEnvironmentStringsW(L"%SystemRoot%\\SysWoW64\\calc.exe", lpwOutPath, szOutPath);
#else
        ExpandEnvironmentStringsW(L"%SystemRoot%\\system32\\calc.exe", lpwOutPath, szOutPath);
#endif
    }
    else {
        ExpandEnvironmentStringsW(L"%SystemRoot%\\system32\\calc.exe", lpwOutPath, szOutPath);
    }
    return true;
}
