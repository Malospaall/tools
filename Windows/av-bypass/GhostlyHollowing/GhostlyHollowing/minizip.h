#include "util.h"
#include "malloc.h"
#include <bcrypt.h>
#include <vector>
#include "minizip/unzip.h"
#include "minizip/mz.h"

#pragma comment(lib, "minizip/lzma.lib")
#pragma comment(lib, "minizip/bzip2.lib")
#pragma comment(lib, "minizip/minizip.lib")
#pragma comment(lib, "minizip/zlibstatic-ng.lib")
#pragma comment(lib, "minizip/libzstd_static.lib")
#pragma comment(lib, "bcrypt.lib")

bool unzip_payload(
    _In_ const std::string& zipFilePath,
    _In_ const std::string& password,
    _In_ const std::string& payloadFileName,
    _Out_ PBYTE* memoryBuffer,
    _Out_ size_t* payloadSize
);