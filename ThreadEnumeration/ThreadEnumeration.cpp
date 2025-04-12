#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <algorithm>

typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(
    HANDLE ThreadHandle,
    THREAD_INFORMATION_CLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );

ULONG_PTR GetThreadStartAddress(HANDLE hThread) {
    pNtQueryInformationThread NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");

    if (!NtQueryInformationThread)
        return 0;

    ULONG_PTR startAddress = 0;
    NTSTATUS status = NtQueryInformationThread(
        hThread,
        (THREAD_INFORMATION_CLASS)9, // ThreadQuerySetWin32StartAddress
        &startAddress,
        sizeof(ULONG_PTR),
        NULL
    );

    if (status != 0)
        return 0;

    return startAddress;
}

bool IsAddressInModule(HANDLE hProcess, LPVOID address, const std::vector<HMODULE>& modules) {
    MODULEINFO moduleInfo;
    for (HMODULE hModule : modules) {
        if (GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo))) {
            if (address >= moduleInfo.lpBaseOfDll && address < (LPBYTE)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage) {
                return true;
            }
        }
    }
    return false;
}

std::vector<HMODULE> GetProcessModules(HANDLE hProcess) {
    std::vector<HMODULE> modules;
    DWORD bytesNeeded;

    if (!EnumProcessModules(hProcess, nullptr, 0, &bytesNeeded)) {
        return modules;
    }

    modules.resize(bytesNeeded / sizeof(HMODULE));

    if (!EnumProcessModules(hProcess, modules.data(), bytesNeeded, &bytesNeeded)) {
        modules.clear();
        return modules;
    }

    modules.resize(bytesNeeded / sizeof(HMODULE));
    return modules;
}

void DetectManualMapping() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create snapshot: " << GetLastError() << std::endl;
        return;
    }

    DWORD currentProcessId = GetCurrentProcessId();
    HANDLE hProcess = GetCurrentProcess();
    auto modules = GetProcessModules(hProcess);

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32)) {
        std::cerr << "Thread32First failed: " << GetLastError() << std::endl;
        CloseHandle(hSnapshot);
        return;
    }

    do {
        if (te32.th32OwnerProcessID != currentProcessId) {
            continue;
        }

        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
        if (hThread == nullptr) {
            continue;
        }

        ULONG_PTR startAddress = GetThreadStartAddress(hThread);

        if (!IsAddressInModule(hProcess, (PVOID)startAddress, modules))
            std::cout << "Suspicious thread detected! ID: " << te32.th32ThreadID << ", Start Address: 0x" << std::hex << startAddress << std::dec << std::endl;
        

    } while (Thread32Next(hSnapshot, &te32));
    CloseHandle(hSnapshot);
}

int main()
{
    std::cout << "Starting manual DLL detection via thread analysis..." << std::endl;
    DetectManualMapping();
    std::cout << "Detection complete..." << std::endl;

    __debugbreak();
    return 0;
}
