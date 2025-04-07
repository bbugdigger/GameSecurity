#include <ntifs.h>

#include "Undefined.h"

EXTERN_C NTSTATUS NTAPI ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

NTSTATUS IsProcRunning(const wchar_t* ProcessName) {
    NTSTATUS Status = STATUS_NOT_FOUND;
    ULONG BufferSize = 0;
    PVOID Buffer = nullptr;

    if (!ProcessName) {
        KdPrint(("ProcessName is NULL\n"));
        return STATUS_INVALID_PARAMETER;
    }

    for (int Attempt = 0; Attempt < 5; Attempt++) {
        Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, BufferSize, 'Proc');
        if (!Buffer) {
            KdPrint(("Failed to allocate %lu bytes for process information\n", BufferSize));
            BufferSize >>= 1;
            continue;
        }

        Status = ZwQuerySystemInformation(SystemProcessInformation, Buffer, BufferSize, &BufferSize);

        if (NT_SUCCESS(Status)) {
            break;
        }
        else if (Status == STATUS_INFO_LENGTH_MISMATCH) {
            ExFreePoolWithTag(Buffer, 'Proc');
            Buffer = NULL;
            BufferSize += 16 * 1024;
        }
        else {
            ExFreePoolWithTag(Buffer, 'Proc');
            KdPrint(("ZwQuerySystemInformation failed: 0x%X\n", Status));
            return Status;
        }
    }

    PSYSTEM_PROCESS_INFORMATION ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer;
    while (ProcessInfo->NextEntryOffset != 0) {
        if (ProcessInfo->ImageName.Buffer != NULL && _wcsicmp(ProcessInfo->ImageName.Buffer, ProcessName) == 0) {
            Status = STATUS_SUCCESS;
            break;
        }
        ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)ProcessInfo + ProcessInfo->NextEntryOffset);
    }

    ExFreePoolWithTag(Buffer, 'Proc');
    return Status;
}

const wchar_t* blocklist[] = {
    L"ida.exe", L"x32dbg", L"gdb", L"x64_dbg", L"windbg", L"scyllahide", L"HxD", L"ollydbg", L"procmon64", L"ghidra", L"scyllaHide", L"binary ninja"
};

NTSTATUS DriverEntry() {
	KdPrintEx((0, 0, "[+] Did we enter kernel?\n"));

    for (int i = 0; i < 12; i++)
    {
        if (IsProcRunning(blocklist[i])) {
            KdPrintEx((0, 0, "\t[!] Something that shouldnt is running!\n"));
            break;
        }
    }

    KdPrintEx((0, 0, "[+] Did we find anything?\n"));
}