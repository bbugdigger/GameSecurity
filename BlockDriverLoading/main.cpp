#include <ntifs.h>
#include <ntimage.h>

extern "C" NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);

CHAR Opcodes[6] = {
	0xB8, 0x01, 0x00, 0x00, 0xC0, // mov eax, 0xC0000001 (STATUS_UNSUCCESSFUL)
	0xC3                          // ret
};

VOID Memcpy(PCHAR Destination, PCHAR Source, SIZE_T Size) {
    PMDL Mdl = nullptr;
    PCHAR MappedAddress = nullptr;
    __try {
        if (!Destination || !Source || !Size) {
            KdPrint(("Invalid parameters\n"));
            __leave;
        }

        Mdl = IoAllocateMdl(Destination, (ULONG)Size, FALSE, FALSE, nullptr);
        if (!Mdl) {
            KdPrint(("Failed to allocate MDL\n"));
            __leave;
        }

        MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);

        // Map the locked pages into a kernel-accessible address
        MappedAddress = (PCHAR)MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, nullptr, FALSE, HighPagePriority | MdlMappingNoExecute);

        if (!MappedAddress) {
            KdPrint(("Failed to map locked pages\n"));
            __leave;
        }

        memcpy(MappedAddress, Source, Size);
        KdPrint(("Memory copy completed successfully\n"));
    }
    /*__except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("Executing SEH __except block\n");
    }*/
    __finally {
        // Clean up resources
        if (MappedAddress) {
            MmUnmapLockedPages(MappedAddress, Mdl);
        }
        if (Mdl) {
            MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
        }
    }
}

VOID ImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
	if (ProcessId != (HANDLE)0 || !ImageInfo->ImageBase)
		return;

	PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)((ULONG_PTR)ImageInfo->ImageBase + ((PIMAGE_DOS_HEADER)ImageInfo->ImageBase)->e_lfanew);
	PCHAR EntryPoint = (PCHAR)((ULONG_PTR)ImageInfo->ImageBase + NtHeader->OptionalHeader.AddressOfEntryPoint);
	//Memcpy(EntryPoint, Opcodes, sizeof(Opcodes)); // no need for this since newly loaded driver is in physical memory and not in VA space
    memcpy(EntryPoint, Opcodes, sizeof(Opcodes));
}

NTSTATUS DriverMain(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	KdPrint(("BlockDriverLoading DriverMain entered\n"));

	// Register the image load notification routine; Will this even work if hackers load driver using kdmapper or another vuln driver?
	NTSTATUS Status = PsSetLoadImageNotifyRoutine(ImageNotifyRoutine);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("PsSetLoadImageNotifyRoutine Failed With Status 0x%08X", Status);
		return Status;
	}
}

NTSTATUS DriverEntry() {
	KdPrintEx((0, 0, "[+] Did we enter kernel?\n"));

	UNICODE_STRING DriverName;
	RtlInitUnicodeString(&DriverName, L"\\Driver\\BlockDriverLoading");

	return IoCreateDriver(&DriverName, &DriverMain);
}