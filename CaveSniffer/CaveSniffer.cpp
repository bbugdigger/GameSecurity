#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>
#include <psapi.h>

struct CodeCave {
    DWORD startAddress;
    DWORD size;
};

bool IsExecutable(DWORD protect) {
    return  (protect & PAGE_EXECUTE) ||
            (protect & PAGE_EXECUTE_READ) ||
            (protect & PAGE_EXECUTE_READWRITE) ||
            (protect & PAGE_EXECUTE_WRITECOPY);
}

std::vector<CodeCave> FindCodeCaves(HANDLE hProcess) {
    std::vector<CodeCave> caves;

    MEMORY_BASIC_INFORMATION memInfo;
    LPVOID address = 0;

    while (VirtualQueryEx(hProcess, address, &memInfo, sizeof(memInfo))) {
        if (IsExecutable(memInfo.Protect)) {
            std::vector<BYTE> memContent(memInfo.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, memInfo.BaseAddress, memContent.data(), memInfo.RegionSize, &bytesRead)) {
                DWORD caveStart = 0;
                DWORD caveSize = 0;

                for (int i = 0; i < bytesRead; i++) {
                    if (memContent[i] == 0x00 || memContent[i] == 0xCC) {
                        if (caveSize == 0)
                            caveStart = (DWORD)memInfo.BaseAddress + i;

                        caveSize++;
                    }
                    else {
                        if (caveSize >= 16)
                        {
                            CodeCave cave;
                            cave.startAddress = caveStart;
                            cave.size = caveSize;
                            caves.push_back(cave);
                        }
                        caveSize = 0;
                    }
                }

                // check if we ended with a cave
                if (caveSize >= 16) {
                    CodeCave cave;
                    cave.startAddress = caveStart;
                    cave.size = caveSize;
                    caves.push_back(cave);
                }
            }
        }

        address = (LPVOID)((ULONG_PTR)memInfo.BaseAddress + memInfo.RegionSize);
    }

    return caves;
}

int main(int argc, char* argv[])
{
    DWORD pid = 27872;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (hProcess == NULL) {
        std::cerr << "OpenProcess Error: " << GetLastError() << std::endl;
        return 1;
    }

    std::vector<CodeCave> caves = FindCodeCaves(hProcess);

    std::cout << "Found " << caves.size() << " code caves" << std::endl;
    /*for (const auto& cave : caves) {
        std::cout << "Start: 0x" << std::hex << cave.startAddress << ", Size: " << std::dec << cave.size << " bytes" << std::endl;
    }*/

    CloseHandle(hProcess);
}
