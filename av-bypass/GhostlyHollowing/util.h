#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include "settings.h"

#ifdef _DEBUG
#include <iostream>
#define DEBUG_MSG(msg) std::cout << "[DEBUG] " << msg;
#define DEBUG_MSGW(msg) std::wcout << "[DEBUG] " << msg;
#define DEBUG_ERR(msg) std::cerr << "[ERROR] " << msg;
#define DEBUG_WRN(msg) std::wcout << "[WARNING] " << msg;
#else
#define DEBUG_MSG(msg)
#define DEBUG_MSGW(msg)
#define DEBUG_ERR(msg)
#define DEBUG_WRN(msg)
#endif

BYTE *buffer_payload(wchar_t *filename, OUT size_t &r_size);
void free_buffer(BYTE* buffer);

//get file name from the full path
wchar_t* get_file_name(wchar_t *full_path);

wchar_t* get_directory(IN wchar_t *full_path, OUT wchar_t *out_buf, IN const size_t out_buf_size);

bool get_calc_path(LPWSTR lpwOutPath, DWORD szOutPath, bool isPayl32bit);

VOID PrintByteArray(_In_ PBYTE pByte, _In_ SIZE_T sSize);

#ifdef _DROPPER

bool WebRequest(
    const std::string& host,
    const int& port,
    std::string& path,
    std::string& zipFilePath,
    std::string& password,
    std::string& payloadFileName
);

#endif