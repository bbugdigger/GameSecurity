#include <ntifs.h>

extern "C" NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);

VOID ImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
	// ...
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