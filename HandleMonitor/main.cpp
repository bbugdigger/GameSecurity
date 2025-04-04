#include <ntifs.h>

#define PROCESS_TERMINATE			0x0001
#define PROCESS_VM_READ				0x0010
#define PROCESS_VM_WRITE			0x0020
#define PROCESS_QUERY_INFORMATION 	0x0400
#define PROCESS_VM_OPERATION  		0x0008

OB_PREOP_CALLBACK_STATUS OnPreOpenProcessHandle(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);

EXTERN_C LPCSTR NTAPI PsGetProcessImageFileName(PEPROCESS Process);

extern "C" NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING) {
	KdPrint(("HandleMonitor DriverEntry entered\n"));

	PVOID RegistrationHandle;

	// Create Device
	PDEVICE_OBJECT DeviceObject = nullptr;
	UNICODE_STRING SymLink = RTL_CONSTANT_STRING(L"\\??\\HandleMonitor");
	UNICODE_STRING DevName = RTL_CONSTANT_STRING(L"\\Device\\HandleMonitor");
	auto Status = IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("Failed to create device (0x%08X)\n", Status));
		return Status;
	}
	Status = IoCreateSymbolicLink(&SymLink, &DevName);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("Failed to create sym link (0x%08X)\n", Status));
		return Status;
	}

	// Register Callback
	OB_OPERATION_REGISTRATION Operations[] = {
		{
			PsProcessType, // object type that triggers the callback routine
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			OnPreOpenProcessHandle, // The system calls this routine before the requested operation occurs. 
			nullptr // The system calls this routine after the requested operation occurs.
		}
	};
	OB_CALLBACK_REGISTRATION Registration = {
		OB_FLT_REGISTRATION_VERSION,
		1, // operation count
		RTL_CONSTANT_STRING(L"12345.6789"), // altitude
		nullptr, // context
		Operations
	};

	Status = ObRegisterCallbacks(&Registration, &RegistrationHandle);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("Failed to register callbacks (status=%08X)\n", Status));
		return Status;
	}

	// done
	KdPrint(("HandleMonitor DriverEntry completed successfully\n"));
	return Status;
}

OB_PREOP_CALLBACK_STATUS OnPreOpenProcessHandle(PVOID /*RegistrationContext*/, POB_PRE_OPERATION_INFORMATION Info) {
	if (Info->KernelHandle)
		return OB_PREOP_SUCCESS;

	auto process = (PEPROCESS)Info->Object; //A pointer to the process or thread object that is the target of the handle operation
	LPCSTR processName = PsGetProcessImageFileName(process);
	if (_stricmp(processName, "cs2.exe")) {

		PEPROCESS CallerProcess = PsGetCurrentProcess();
		LPCSTR callerName = PsGetProcessImageFileName(CallerProcess);
		if (_stricmp(callerName, "lsass.exe") == 0) {
			KdPrint(("Hopefully this wont crash the system\n"));
			// we might wana be carefull about lsass case since its maybe protected by PatchGuard ?!?!
			Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			return OB_PREOP_SUCCESS;
		}

		// if this is a handle to the game, strip access flags
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_INFORMATION;
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
	}

	return OB_PREOP_SUCCESS;
}