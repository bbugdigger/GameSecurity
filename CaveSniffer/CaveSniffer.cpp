#include <iostream>
#include <fstream>
#include <vector>
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <algorithm>

struct CodeCave {
    UINT_PTR startAddress;
    SIZE_T size;

    UINT_PTR endAddress() const {
        return startAddress + size;
    }

    bool isAdjacent(const CodeCave& other) const {
        return (other.startAddress <= this->endAddress()) && (other.endAddress() >= this->startAddress);
    }
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

std::vector<CodeCave> MergeCaves(std::vector<CodeCave> caves) {
    if (caves.empty()) 
        return caves;

    std::vector<CodeCave> merged;
    CodeCave current = caves[0];

    for (size_t i = 1; i < caves.size(); i++) {
        if (current.isAdjacent(caves[i])) {
            UINT_PTR newStart = std::min(current.startAddress, caves[i].startAddress);
            UINT_PTR newEnd = std::max(current.endAddress(), caves[i].endAddress());
            current.startAddress = newStart;
            current.size = newEnd - newStart;
        }
        else {
            merged.push_back(current);
            current = caves[i];
        }
    }
    merged.push_back(current);

    return merged;
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
    std::vector<CodeCave> mergedCaves = MergeCaves(FindCodeCaves(hProcess));

    std::cout << "Found " << caves.size() << " code caves" << std::endl;
    std::cout << "Found " << mergedCaves.size() << " merged code caves" << std::endl;
    
    CloseHandle(hProcess);
}
