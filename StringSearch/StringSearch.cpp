#include <iostream>
#include <fstream>
#include <vector>
#include <set>
#include <algorithm>
#include <string>
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

struct ExecutableSection {
    UINT_PTR startAddress;
    SIZE_T size;
    std::string moduleName;

    UINT_PTR endAddress() const {
        return startAddress + size;
    }
};

const std::vector<std::string> PE_IDENTIFIER_STRINGS = {
    "This program cannot be run in DOS mode",
    "Rich",
    ".text",
    ".rdata",
    ".data",
    ".rsrc",
    ".reloc",
    "VCRUNTIME140.dll",
    "msvcp",
    "msvcr",
    "api-ms-win-crt",
    "KERNEL32.dll",
    "USER32.dll",
    "GDI32.dll",
    "ADVAPI32.dll"
};

const std::vector<std::string> SYSTEM_DLLS = {
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "wintrust.dll",
    "VCRUNTIME140.dll",
    "ucrtbase.dll",
    "ucrtbased.dll",
    "msvcrt.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "apphelp.dll",
    "shell32.dll",
    "ole32.dll",
    "comdlg32.dll",
    "shlwapi.dll",
    "ws2_32.dll"
};

bool IsExecutable(DWORD protect) {
    return  (protect & PAGE_EXECUTE) ||
            (protect & PAGE_EXECUTE_READ) ||
            (protect & PAGE_EXECUTE_READWRITE) ||
            (protect & PAGE_EXECUTE_WRITECOPY);
}

std::string GetModuleName(HANDLE hProcess, UINT_PTR address) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                if (address >= (UINT_PTR)modInfo.lpBaseOfDll &&
                    address < (UINT_PTR)modInfo.lpBaseOfDll + modInfo.SizeOfImage) {
                    char szModName[MAX_PATH];
                    if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                        PathStripPathA(szModName);
                        return szModName;
                    }
                }
            }
        }
    }
    return "";
}

bool IsSystemModule(const std::string& moduleName) {
    std::string lowerModule = moduleName;
    std::transform(lowerModule.begin(), lowerModule.end(), lowerModule.begin(), ::tolower);

    for (const auto& systemDll : SYSTEM_DLLS) {
        std::string lowerSystemDll = systemDll;
        std::transform(lowerSystemDll.begin(), lowerSystemDll.end(), lowerSystemDll.begin(), ::tolower);

        if (lowerModule.find(lowerSystemDll) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::vector<ExecutableSection> FindExecutableSections(HANDLE hProcess) {
    std::vector<ExecutableSection> exeSections;

    MEMORY_BASIC_INFORMATION memInfo;
    UINT_PTR address = 0;

    while (VirtualQueryEx(hProcess, (LPCVOID)address, &memInfo, sizeof(memInfo))) {
        if (memInfo.State == MEM_COMMIT && IsExecutable(memInfo.Protect)) {
            std::string moduleName = GetModuleName(hProcess, address);

            ExecutableSection section;
            section.startAddress = address;
            section.size = memInfo.RegionSize;
            section.moduleName = moduleName;

            exeSections.push_back(section);
        }

        address += memInfo.RegionSize;
        if (address == 0) {
            break; // Overflow
        }
    }

    return exeSections;
}

std::vector<std::string> SearchForPEStrings(HANDLE hProcess, const ExecutableSection& section) {
    std::vector<std::string> foundStrings;

    // Read the entire section
    std::vector<char> buffer(section.size);
    SIZE_T bytesRead;
    if (ReadProcessMemory(hProcess, (LPCVOID)section.startAddress, buffer.data(), section.size, &bytesRead)) {
        std::string sectionContent(buffer.begin(), buffer.end());

        // Search for each PE identifier string
        for (const auto& peString : PE_IDENTIFIER_STRINGS) {
            if (sectionContent.find(peString) != std::string::npos) {
                foundStrings.push_back(peString);
            }
        }
    }

    return foundStrings;
}

void DetectManualMapping() {
    DWORD pid = GetCurrentProcessId();

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process: " << GetLastError() << std::endl;
        return;
    }

    std::vector<ExecutableSection> exeSections = FindExecutableSections(hProcess);
    std::cout << "Found " << exeSections.size() << " executable sections" << std::endl;

    for (const auto& section : exeSections) {
        if (IsSystemModule(section.moduleName)) {
            continue;
        }

        std::vector<std::string> foundStrings = SearchForPEStrings(hProcess, section);
        if (!foundStrings.empty()) {
            std::cout << "Suspicious section found in " << (section.moduleName.empty() ? "unknown module" : section.moduleName)
                << " at " << std::hex << section.startAddress << "-" << section.endAddress() << std::dec << std::endl;

            std::cout << "Found PE identifiers:" << std::endl;
            for (const auto& str : foundStrings) {
                std::cout << "  - " << str << std::endl;
            }

            // Here you would typically log this detection or take action
        }
    }

    CloseHandle(hProcess);
}

int main()
{
    std::cout << "Starting manual DLL detection via string analysis..." << std::endl;
    DetectManualMapping();
    std::cout << "Detection complete..." << std::endl;

    __debugbreak();
    return 0;
}
