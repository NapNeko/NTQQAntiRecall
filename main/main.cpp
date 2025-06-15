#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>

HANDLE MainProcessHandle = NULL;

// PE手动映射结构
typedef struct _MANUAL_MAPPING_DATA
{
    LPVOID ImageBase;
    HMODULE(WINAPI *fnLoadLibraryA)(LPCSTR);
    FARPROC(WINAPI *fnGetProcAddress)(HMODULE, LPCSTR);
} MANUAL_MAPPING_DATA, *PMANUAL_MAPPING_DATA;

// Shellcode for manual mapping execution
DWORD WINAPI ManualMappingShell(PMANUAL_MAPPING_DATA pData);
void __stdcall ShellcodeEnd();

// 读取DLL文件到内存
std::vector<BYTE> ReadDllFile(const std::wstring &dllPath)
{
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        std::wcerr << L"Failed to open DLL file: " << dllPath << std::endl;
        return {};
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<BYTE> buffer(size);
    if (!file.read(reinterpret_cast<char *>(buffer.data()), size))
    {
        std::wcerr << L"Failed to read DLL file" << std::endl;
        return {};
    }

    return buffer;
}

// 手动映射DLL到远程进程
bool ManualMapDll(HANDLE hProcess, const std::vector<BYTE> &dllData)
{
    if (dllData.size() < sizeof(IMAGE_DOS_HEADER))
    {
        std::wcerr << L"Invalid DLL data size" << std::endl;
        return false;
    }

    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(const_cast<BYTE *>(dllData.data()));
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::wcerr << L"Invalid DOS header" << std::endl;
        return false;
    }

    if (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > dllData.size())
    {
        std::wcerr << L"Invalid PE structure" << std::endl;
        return false;
    }

    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(const_cast<BYTE *>(dllData.data()) + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        std::wcerr << L"Invalid NT header" << std::endl;
        return false;
    }

    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        std::wcerr << L"Unsupported architecture" << std::endl;
        return false;
    }

    // 在远程进程中分配内存
    LPVOID pImageBase = VirtualAllocEx(hProcess, nullptr, pNtHeaders->OptionalHeader.SizeOfImage,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImageBase)
    {
        std::wcerr << L"Failed to allocate memory in target process, error: " << GetLastError() << std::endl;
        return false;
    }

    // 复制PE头部
    if (!WriteProcessMemory(hProcess, pImageBase, dllData.data(), pNtHeaders->OptionalHeader.SizeOfHeaders, nullptr))
    {
        std::wcerr << L"Failed to write PE headers, error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
        return false;
    }

    // 复制各个节
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader)
    {
        if (pSectionHeader->SizeOfRawData == 0 || pSectionHeader->PointerToRawData == 0)
            continue;

        if (pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData > dllData.size())
        {
            std::wcerr << L"Invalid section data" << std::endl;
            VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
            return false;
        }

        LPVOID pSectionDest = reinterpret_cast<LPVOID>(reinterpret_cast<ULONG_PTR>(pImageBase) + pSectionHeader->VirtualAddress);
        const BYTE *pSectionSrc = dllData.data() + pSectionHeader->PointerToRawData;

        if (!WriteProcessMemory(hProcess, pSectionDest, pSectionSrc, pSectionHeader->SizeOfRawData, nullptr))
        {
            std::wcerr << L"Failed to write section: " << i << L", error: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
            return false;
        }
    }

    // 准备手动映射数据
    MANUAL_MAPPING_DATA mappingData = {};
    mappingData.ImageBase = pImageBase;
    mappingData.fnLoadLibraryA = LoadLibraryA;
    mappingData.fnGetProcAddress = GetProcAddress;

    // 分配数据结构内存
    LPVOID pMappingData = VirtualAllocEx(hProcess, nullptr, sizeof(MANUAL_MAPPING_DATA),
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMappingData)
    {
        std::wcerr << L"Failed to allocate mapping data memory, error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pMappingData, &mappingData, sizeof(MANUAL_MAPPING_DATA), nullptr))
    {
        std::wcerr << L"Failed to write mapping data, error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMappingData, 0, MEM_RELEASE);
        return false;
    }

    // 分配shellcode内存
    DWORD shellcodeSize = reinterpret_cast<DWORD_PTR>(ShellcodeEnd) - reinterpret_cast<DWORD_PTR>(ManualMappingShell);
    LPVOID pShellcode = VirtualAllocEx(hProcess, nullptr, shellcodeSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcode)
    {
        std::wcerr << L"Failed to allocate shellcode memory, error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMappingData, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pShellcode, ManualMappingShell, shellcodeSize, nullptr))
    {
        std::wcerr << L"Failed to write shellcode, error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMappingData, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        return false;
    }

    // 创建远程线程执行shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                        reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode),
                                        pMappingData, 0, nullptr);
    if (!hThread)
    {
        std::wcerr << L"Failed to create remote thread, error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pImageBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMappingData, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        return false;
    }

    // 等待执行完成
    DWORD waitResult = WaitForSingleObject(hThread, 10000); // 10秒超时
    if (waitResult != WAIT_OBJECT_0)
    {
        std::wcerr << L"Shellcode execution timeout or failed" << std::endl;
    }

    CloseHandle(hThread);

    // 清理内存
    VirtualFreeEx(hProcess, pMappingData, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);

    std::wcout << L"Manual DLL mapping completed successfully" << std::endl;
    return true;
}

// 手动映射执行的shellcode
DWORD WINAPI ManualMappingShell(PMANUAL_MAPPING_DATA pData)
{
    if (!pData || !pData->ImageBase)
        return FALSE;

    BYTE *pBase = reinterpret_cast<BYTE *>(pData->ImageBase);
    PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBase);

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + pDosHeader->e_lfanew);

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // 处理导入表
    PIMAGE_DATA_DIRECTORY pImportDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportDir->Size && pImportDir->VirtualAddress)
    {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pBase + pImportDir->VirtualAddress);

        while (pImportDesc->Name)
        {
            char *szModuleName = reinterpret_cast<char *>(pBase + pImportDesc->Name);
            HMODULE hModule = pData->fnLoadLibraryA(szModuleName);

            if (!hModule)
            {
                ++pImportDesc;
                continue;
            }

            ULONG_PTR *pThunkRef = nullptr;
            ULONG_PTR *pFuncRef = reinterpret_cast<ULONG_PTR *>(pBase + pImportDesc->FirstThunk);

            if (pImportDesc->OriginalFirstThunk)
                pThunkRef = reinterpret_cast<ULONG_PTR *>(pBase + pImportDesc->OriginalFirstThunk);
            else
                pThunkRef = pFuncRef;

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
            {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
                {
                    *pFuncRef = reinterpret_cast<ULONG_PTR>(pData->fnGetProcAddress(hModule,
                                                                                    reinterpret_cast<char *>(*pThunkRef & 0xFFFF)));
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(pBase + *pThunkRef);
                    *pFuncRef = reinterpret_cast<ULONG_PTR>(pData->fnGetProcAddress(hModule, pImport->Name));
                }
            }
            ++pImportDesc;
        }
    }

    // 处理重定位表
    PIMAGE_DATA_DIRECTORY pRelocDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (pRelocDir->Size && pRelocDir->VirtualAddress)
    {
        ULONG_PTR delta = reinterpret_cast<ULONG_PTR>(pBase) - pNtHeaders->OptionalHeader.ImageBase;
        if (delta)
        {
            PIMAGE_BASE_RELOCATION pReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pBase + pRelocDir->VirtualAddress);

            while (pReloc->VirtualAddress && pReloc->SizeOfBlock)
            {
                WORD *pRelocData = reinterpret_cast<WORD *>(pReloc + 1);
                DWORD numEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

                for (DWORD i = 0; i < numEntries; ++i, ++pRelocData)
                {
                    WORD type = *pRelocData >> 12;
                    WORD offset = *pRelocData & 0xFFF;

                    if (type == IMAGE_REL_BASED_DIR64)
                    {
                        ULONG_PTR *pPatch = reinterpret_cast<ULONG_PTR *>(pBase + pReloc->VirtualAddress + offset);
                        *pPatch += delta;
                    }
                }
                pReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE *>(pReloc) + pReloc->SizeOfBlock);
            }
        }
    }

    // 调用DLL入口点
    if (pNtHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        typedef BOOL(WINAPI * DllMainFunc)(HMODULE, DWORD, LPVOID);
        DllMainFunc fnDllMain = reinterpret_cast<DllMainFunc>(pBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        fnDllMain(reinterpret_cast<HMODULE>(pBase), DLL_PROCESS_ATTACH, nullptr);
    }

    return TRUE;
}

void __stdcall ShellcodeEnd() { return; }

void CreateSuspendedProcessWithManualMapping(const wchar_t *processName, const wchar_t *dllPath)
{
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFOW));

    // 使用简单的进程创建
    if (!CreateProcessW(NULL, (LPWSTR)processName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        DWORD error = GetLastError();
        std::wcerr << L"Error Code: " << error << std::endl;
        std::wcerr << L"Process Path: " << processName << std::endl;
        std::wcerr << L"Failed to start process." << std::endl;
        return;
    }

    MainProcessHandle = pi.hProcess;
    std::wcout << L"[NapCat Backend] Main Process ID:" << pi.dwProcessId << std::endl;

    // 等待进程初始化
    Sleep(1000);

    // 读取DLL文件
    std::vector<BYTE> dllData = ReadDllFile(dllPath);
    if (dllData.empty())
    {
        std::wcerr << L"Failed to read DLL file" << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }

    // 执行手动映射注入
    if (!ManualMapDll(pi.hProcess, dllData))
    {
        std::wcerr << L"Manual mapping failed" << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }

    // 恢复主线程
    ResumeThread(pi.hThread);

    // 等待进程结束
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

void signalHandler(int signum)
{
    if (MainProcessHandle != NULL)
    {
        std::cout << "[NapCat Backend] Terminate Main Process." << std::endl;
        TerminateProcess(MainProcessHandle, 0);
    }
    exit(signum);
}

std::wstring getFullPath(const std::wstring &relativePath)
{
    wchar_t szFullPath[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, szFullPath);
    std::wstring fullPath = szFullPath;
    fullPath += L"\\" + relativePath;
    return fullPath;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
    std::wstring QQPath = getFullPath(L"QQ.exe");
    std::wstring QQInjectDll = getFullPath(L"NapCatWinBootHook.dll");

    // 检查文件是否存在
    if (GetFileAttributesW(QQPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        std::wcerr << L"QQ.exe not found: " << QQPath << std::endl;
        return 1;
    }

    if (GetFileAttributesW(QQInjectDll.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        std::wcerr << L"DLL not found: " << QQInjectDll << std::endl;
        return 1;
    }

    CreateSuspendedProcessWithManualMapping(QQPath.c_str(), QQInjectDll.c_str());
    return 0;
}