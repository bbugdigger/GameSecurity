#include <ntifs.h>

#define PROCESS_CREATE_THREAD		0x0002
#define PROCESS_TERMINATE			0x0001
#define PROCESS_VM_READ				0x0010
#define PROCESS_VM_WRITE			0x0020
#define PROCESS_QUERY_INFORMATION 	0x0400
#define PROCESS_VM_OPERATION  		0x0008

OB_PREOP_CALLBACK_STATUS OnPreThreadHandle(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info);

EXTERN_C LPCSTR NTAPI PsGetProcessImageFileName(PEPROCESS Process);
EXTERN_C BOOLEAN NTAPI PsIsProcessBeingDebugged(PEPROCESS Process);

NTSTATUS DriverEntry() {
	KdPrintEx((0, 0, "[+] Did we enter kernel?\n"));

	PVOID RegistrationHandle;

	// Register Callback
	OB_OPERATION_REGISTRATION Operations[] = {
		{
			PsThreadType, // object type that triggers the callback routine
			OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
			OnPreThreadHandle, // The system calls this routine before the requested operation occurs. 
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

	auto Status = ObRegisterCallbacks(&Registration, &RegistrationHandle);
	if (!NT_SUCCESS(Status)) {
		KdPrint(("Failed to register callbacks (status=%08X)\n", Status));
		return Status;
	}

	// done
	KdPrint(("DriverEntry completed successfully\n"));
	return Status;
}

OB_PREOP_CALLBACK_STATUS OnPreThreadHandle(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info) {
	if (Info->KernelHandle)
		return OB_PREOP_SUCCESS;
	
	PEPROCESS TargetProcess = (PEPROCESS)Info->Object;
	PEPROCESS CallerProcess = PsGetCurrentProcess();
	LPCSTR TargetName = PsGetProcessImageFileName(TargetProcess);
	LPCSTR CallerName = PsGetProcessImageFileName(CallerProcess);

	BOOLEAN IsDebugged = PsIsProcessBeingDebugged(TargetProcess);

	if (!IsDebugged) {
		Info->Parameters->CreateHandleInformation.DesiredAccess &= ~(
			PROCESS_CREATE_THREAD |
			PROCESS_TERMINATE |
			PROCESS_VM_READ |
			PROCESS_VM_WRITE |
			PROCESS_QUERY_INFORMATION |
			PROCESS_VM_OPERATION
		);
	}

	if ((Info->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_CREATE_THREAD) &&
		!(Info->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_CREATE_THREAD)) {
		KdPrint(("Blocked thread creation access from %s to %s\n", CallerName, TargetName));
	}

	return OB_PREOP_SUCCESS;
}