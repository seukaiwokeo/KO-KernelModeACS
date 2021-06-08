#include "XCode.h"

char ForbiddenDrivers[39][50] = { 
	"dbk32.sys",
	"dbk64.sys",
	"windowskernelexplorer.sys",
	"ksdumperdriver.sys",
	"capcom.sys",
	"iqvw64e.sys",
	"iqvw32.sys",
	"adv64drv.sys",
	"agent64.sys",
	"alsysio64.sys",
	"amifldrv64.sys",
	"asio.sys",
	"asrautochkupddrv.sys",
	"asrdrv10.sys",
	"asrdrv101.sys",
	"asribdrv.sys",
	"asromgdrv.sys",
	"asrrapidstartdrv.sys",
	"asrsmartconnectdrv.sys",
	"asupio.sys",
	"atillk64.sys",
	"bs_def64.sys",
	"asupio.sys",
	"atillk64.sys",
	"citmdrv_amd64.sys",
	"citmdrv_ia64.sys",
	"cpuz_x64.sys",
	"glckio2.sys",
	"inpoutx64.sys",
	"kprocesshacker.sys",
	"rzpnk.sys",
	"v0edkxsuivz.sys",
	"gdrv.sys",
	"driver.sys",
	"pchunter",
	"macromap",
	"kdmapper",
	"blekbon",
	"blackbone"
};

VOID THMain(PVOID Context);
VOID KillProcess(ULONG PID);
NTSTATUS RegisterCallbackFunction(BOOLEAN ObProcess);
NTSTATUS UnRegisterCallbackFunction(BOOLEAN ObProcess);
OB_PREOP_CALLBACK_STATUS ObjectPreCallbackProcess(PVOID pRegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInfo);
OB_PREOP_CALLBACK_STATUS ObjectPreCallbackThread(PVOID pRegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInfo);

ULONG KO_ID[2] = { 0,0 }, XCodeAddress;
PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING dev, dos;
HANDLE procIDS;
PVOID pObProcHandle, pObThreadHandle;
PETHREAD pThreadObject, pScanThreadObject;

BOOLEAN ObProcStillValid, ObThreadStillValid, PsStillValid;
BOOLEAN Unload;

LONG GetAvaliableKOID()
{
	if (!KO_ID[0]) return 0;
	else if (!KO_ID[1]) return 1;
	else return -1;
}

NTSTATUS KeReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(),TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}

NTSTATUS KeWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process,TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}

PLOAD_IMAGE_NOTIFY_ROUTINE ImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
	LONG AvaliableIndex = GetAvaliableKOID();

	if(AvaliableIndex == -1)
		return STATUS_UNSUCCESSFUL;

	if (wcsstr(FullImageName->Buffer, L"\\XCode\\XCode.dll")) {
		DebugMessage("XCode::Kernel -> Loaded To Process: %p \n", ProcessId);
		XCodeAddress = (ULONG)ImageInfo->ImageBase;
		KO_ID[AvaliableIndex] = (ULONG)ProcessId;
		return STATUS_SUCCESS;
	}

	if (KO_ID[0] == (ULONG)ProcessId || KO_ID[1] == (ULONG)ProcessId) {

		if (wcsstr(FullImageName->Buffer, L"speedhack-i386") || wcsstr(FullImageName->Buffer, L"speedhack-x86_64")) {
			KillProcess(KO_ID[0]);
			KillProcess(KO_ID[1]);
		}
	}

	return STATUS_SUCCESS;
}

PCREATE_PROCESS_NOTIFY_ROUTINE CreateProcessCallback(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	if (!Create && (KO_ID[0] != 0 || KO_ID[1] != 0))
	{
		if(KO_ID[0] == ProcessId)
			KO_ID[0] = 0;
		else if (KO_ID[1] == ProcessId)
			KO_ID[1] = 0;

		DebugMessage("XCode::Kernel -> Game ended");
	}

	return STATUS_SUCCESS;
}

NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG BytesIO = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	ULONG ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (ControlCode == IO_READ_REQUEST)
	{
		PKERNEL_READ_REQUEST ReadInput = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		PKERNEL_READ_REQUEST ReadOutput = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ReadInput->ProcessId, &Process)))
			KeReadVirtualMemory(Process, ReadInput->Address,
				&ReadInput->Response, ReadInput->Size);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_READ_REQUEST);
	}
	else if (ControlCode == IO_WRITE_REQUEST)
	{
		PKERNEL_WRITE_REQUEST WriteInput = (PKERNEL_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;
		if (NT_SUCCESS(PsLookupProcessByProcessId(WriteInput->ProcessId, &Process)))
			KeWriteVirtualMemory(Process, &WriteInput->Value,WriteInput->Address, WriteInput->Size);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(KERNEL_WRITE_REQUEST);
	}
	else if (ControlCode == IO_GET_ID_REQUEST)
	{
		PULONG OutPut = (PULONG)Irp->AssociatedIrp.SystemBuffer;
		*OutPut = KO_ID;
		Status = STATUS_SUCCESS;
		BytesIO = sizeof(*OutPut);
	}
	else if (ControlCode == IO_GET_MODULE_REQUEST)
	{
		PULONG OutPut = (PULONG)Irp->AssociatedIrp.SystemBuffer;
		*OutPut = XCodeAddress;
		Status = STATUS_SUCCESS;
		BytesIO = sizeof(*OutPut);
	}
	else if (ControlCode == IO_END_REQUEST)
	{
		if (KO_ID[0]) {
			KillProcess(KO_ID[0]);
			KO_ID[0] = 0;
			
		}

		if (KO_ID[1]) {
			KillProcess(KO_ID[1]);
			KO_ID[1] = 0;
		}
			
		Status = STATUS_SUCCESS;
		BytesIO = 0;

		DebugMessage("XCode::Kernel -> Game ended");
	}
	else if (ControlCode == IO_PROC_ENVET)
	{
		if (procIDS)
		{
			PULONG OutPut = (PULONG)Irp->AssociatedIrp.SystemBuffer;
			*OutPut = procIDS;
			Status = STATUS_SUCCESS;
			BytesIO = sizeof(*OutPut);
			procIDS = 0;
		}
	}
	else if (ControlCode == IO_CONNECT_EVENT)
	{
		LONG AvaliableIndex = GetAvaliableKOID();
		PULONG OutPut = (PULONG)Irp->AssociatedIrp.SystemBuffer;
		ULONG PID = *OutPut;
		if (AvaliableIndex == -1)
		{
			Status = STATUS_UNSUCCESSFUL;
			KillProcess(PID);
		}
		else {
			
			KO_ID[AvaliableIndex] = PID;
			Status = STATUS_SUCCESS;
		}
		BytesIO = 0;
	}
	else if (ControlCode == IO_HEART_BEAT)
	{
		Status = STATUS_SUCCESS;
		BytesIO = 0;
	}
	else
	{
		Status = STATUS_INVALID_PARAMETER;
		BytesIO = 0;
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

BOOLEAN pre = FALSE;

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	Unload = TRUE;

	KeWaitForSingleObject(pThreadObject, Executive, KernelMode, FALSE, NULL);
	ObDereferenceObject(pThreadObject);

	KeWaitForSingleObject(pScanThreadObject, Executive, KernelMode, FALSE, NULL);
	ObDereferenceObject(pScanThreadObject);

	PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
	PsSetCreateProcessNotifyRoutine(CreateProcessCallback, TRUE);

	PEPROCESS pGame = NULL;

	if (KO_ID[0] && PsLookupProcessByProcessId((HANDLE)KO_ID[0], &pGame) == STATUS_SUCCESS)
	{
		if (pGame) KillProcess(KO_ID[0]);
	}
	if (KO_ID[1] && PsLookupProcessByProcessId((HANDLE)KO_ID[1], &pGame) == STATUS_SUCCESS)
	{
		if (pGame) KillProcess(KO_ID[1]);
	}

	UnRegisterCallbackFunction(TRUE);
	UnRegisterCallbackFunction(FALSE);

	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObject->DeviceObject);

	DebugMessage("XCode::Kernel -> UNLOADED");

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {

	PsSetLoadImageNotifyRoutine(ImageLoadCallback);
	PsSetCreateProcessNotifyRoutine(CreateProcessCallback, FALSE);

	RtlInitUnicodeString(&dev, L"\\Device\\xcodekernel");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\xcodekernel");

	PLDR_DATA_TABLE_ENTRY64 ldrDataTable;
	ldrDataTable = (PLDR_DATA_TABLE_ENTRY64)pDriverObject->DriverSection;
	ldrDataTable->Flags |= 0x20;

	RegisterCallbackFunction(TRUE);
	RegisterCallbackFunction(FALSE);

	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&dos, &dev);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCall;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	pDriverObject->DriverUnload = UnloadDriver;

	if (pDeviceObject) {
		pDeviceObject->Flags |= DO_DIRECT_IO;
		pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	}

	HANDLE hThread = NULL;
	if (PsCreateSystemThread(&hThread, (ACCESS_MASK)0, NULL, (HANDLE)0, NULL, (PKSTART_ROUTINE)THMain, pDeviceObject) == STATUS_SUCCESS)
	{
		ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &pThreadObject, NULL);
		ZwClose(hThread);
	}

	if (PsCreateSystemThread(&hThread, (ACCESS_MASK)0, NULL, (HANDLE)0, NULL, (PKSTART_ROUTINE)DriverScan, pDeviceObject) == STATUS_SUCCESS)
	{
		ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &pScanThreadObject, NULL);
		ZwClose(hThread);
	}

	DebugMessage("XCode::Kernel -> LOADED");

	HANDLE hThreadS = NULL;
	return STATUS_SUCCESS;
}


NTSTATUS RegisterCallbackFunction(BOOLEAN ObProcess)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING Altitude;

	OB_OPERATION_REGISTRATION RegisterOperation;
	OB_CALLBACK_REGISTRATION RegisterCallback;
	REG_CONTEXT RegistrationContext;
	RegistrationContext.ulIndex = 1;
	RegistrationContext.Version = 120;

	RtlSecureZeroMemory(&RegisterOperation, sizeof(OB_OPERATION_REGISTRATION));
	RtlSecureZeroMemory(&RegisterCallback, sizeof(OB_CALLBACK_REGISTRATION));
	RtlSecureZeroMemory(&RegistrationContext, sizeof(REG_CONTEXT));

	if ((USHORT)ObGetFilterVersion() == OB_FLT_REGISTRATION_VERSION)
	{
		if (ObProcess)
		{
			RtlInitUnicodeString(&Altitude, L"WinLoadProcess");
			RegisterOperation.ObjectType = PsProcessType;
			RegisterOperation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
			RegisterOperation.PreOperation = ObjectPreCallbackProcess;
			RegisterOperation.PostOperation = NULL;

			RegisterCallback.Version = OB_FLT_REGISTRATION_VERSION;
			RegisterCallback.OperationRegistrationCount = (USHORT)1;
			RegisterCallback.Altitude = Altitude;
			RegisterCallback.RegistrationContext = &RegistrationContext;
			RegisterCallback.OperationRegistration = &RegisterOperation;

			status = ObRegisterCallbacks(&RegisterCallback, &pObProcHandle);
		}
		else
		{
			RtlInitUnicodeString(&Altitude, L"WinLoadThread");
			RegisterOperation.ObjectType = PsThreadType;
			RegisterOperation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
			RegisterOperation.PreOperation = ObjectPreCallbackThread;
			RegisterOperation.PostOperation = NULL;

			RegisterCallback.Version = OB_FLT_REGISTRATION_VERSION;
			RegisterCallback.OperationRegistrationCount = (USHORT)1;
			RegisterCallback.Altitude = Altitude;
			RegisterCallback.RegistrationContext = &RegistrationContext;
			RegisterCallback.OperationRegistration = &RegisterOperation;
			status = ObRegisterCallbacks(&RegisterCallback, &pObThreadHandle);
		}
	}

	return status;
}

NTSTATUS UnRegisterCallbackFunction(BOOLEAN ObProcess)
{
	if (ObProcess)
	{
		if (pObProcHandle)
		{
			ObUnRegisterCallbacks(pObProcHandle);
			pObProcHandle = NULL;
		}
	}
	else
	{
		if (pObThreadHandle)
		{
			ObUnRegisterCallbacks(pObThreadHandle);
			pObThreadHandle = NULL;
		}
	}

	return STATUS_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS ObjectPreCallbackProcess(PVOID pRegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInfo)
{
	UNREFERENCED_PARAMETER(pRegistrationContext);
	if (!KO_ID[0] && !KO_ID[1])
		return OB_PREOP_SUCCESS;

	PEPROCESS pTargetProcess = (PEPROCESS)pOperationInfo->Object;
	ULONG TargetProcessPID = (ULONG)PsGetProcessId(pTargetProcess);

	ULONG RequesterProcessID = (ULONG)PsGetCurrentProcessId();

	if (pOperationInfo->KernelHandle)
		return OB_PREOP_SUCCESS;

	if (KO_ID[0] || KO_ID[1])
	{
		if (TargetProcessPID == KO_ID[0] || TargetProcessPID == KO_ID[1])
		{
			if (RequesterProcessID == KO_ID[0] || RequesterProcessID == KO_ID[1])
				return OB_PREOP_SUCCESS;

			if (pOperationInfo->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_ALL_ACCESS;

				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;

				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;

				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;

				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_CREATE_THREAD) == PROCESS_CREATE_THREAD)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
			}
			else
			{
				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_ALL_ACCESS;

				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;

				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;

				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;

				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_CREATE_THREAD) == PROCESS_CREATE_THREAD)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;

			}
		}
	}
	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS ObjectPreCallbackThread(PVOID pRegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInfo)
{
	UNREFERENCED_PARAMETER(pRegistrationContext);
	if (!KO_ID[0] && !KO_ID[1])
		return OB_PREOP_SUCCESS;
	PETHREAD pTargetThread = (PETHREAD)pOperationInfo->Object;
	PEPROCESS pTargetProcess = IoThreadToProcess(pTargetThread);
	ULONG TargetProccesID = (ULONG)PsGetProcessId(pTargetProcess);

	PETHREAD pRequesterThread = PsGetCurrentThread();
	PEPROCESS pRequesterProcess = IoThreadToProcess(pRequesterThread);
	ULONG RequesterProcessPID = (ULONG)PsGetProcessId(pRequesterProcess);

	if (pOperationInfo->KernelHandle)
		return OB_PREOP_SUCCESS;

	if (KO_ID[0] || KO_ID[1])
	{
		if (TargetProccesID == KO_ID[0] || TargetProccesID == KO_ID[1])
		{
			if (RequesterProcessPID == KO_ID[0] || RequesterProcessPID == KO_ID[1])
				return OB_PREOP_SUCCESS;

			if (pOperationInfo->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_ALL_ACCESS;

				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & THREAD_SUSPEND_RESUME) == THREAD_SUSPEND_RESUME)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;

				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & THREAD_TERMINATE) == THREAD_TERMINATE)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE;

				if ((pOperationInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess & THREAD_SET_INFORMATION) == THREAD_SET_INFORMATION)
					pOperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SET_INFORMATION;
			}
			else
			{
				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_ALL_ACCESS;

				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & THREAD_SUSPEND_RESUME) == THREAD_SUSPEND_RESUME)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;

				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & THREAD_TERMINATE) == THREAD_TERMINATE)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE;

				if ((pOperationInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & THREAD_SET_INFORMATION) == THREAD_SET_INFORMATION)
					pOperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SET_INFORMATION;
			}
		}
	}

	return OB_PREOP_SUCCESS;
}

VOID KillProcess(ULONG PID)
{
	HANDLE hProc = NULL;
	OBJECT_ATTRIBUTES objA = { 0 };
	CLIENT_ID cid = { 0 };

	cid.UniqueProcess = PID;
	cid.UniqueThread = NULL;
	InitializeObjectAttributes(&objA, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	if (ZwOpenProcess(&hProc, PROCESS_ALL_ACCESS, &objA, &cid) == STATUS_SUCCESS)
		ZwTerminateProcess(hProc, STATUS_SUCCESS);
}

VOID THMain(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);

	LARGE_INTEGER delay = { 0 };
	delay.QuadPart = -1 * (100000);

	while (1)
	{
		if (Unload)
			PsTerminateSystemThread(STATUS_SUCCESS);

		if (RegisterCallbackFunction(TRUE) != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION)
		{
			ObProcStillValid = FALSE;
			if (KO_ID[0]) KillProcess(KO_ID[0]);
			if (KO_ID[1]) KillProcess(KO_ID[1]);
		}

		if (RegisterCallbackFunction(FALSE) != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION)
		{
			ObThreadStillValid = FALSE;
			if (KO_ID[0]) KillProcess(KO_ID[0]);
			if (KO_ID[1]) KillProcess(KO_ID[1]);
		}
		KeDelayExecutionThread(KernelMode, FALSE, &delay);
	}
}

VOID DriverScan(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);

	LARGE_INTEGER delay;
	delay.QuadPart = DELAY_ONE_MILLISECOND;
	delay.QuadPart *= 50;

	while (1)
	{
		if (Unload)
			PsTerminateSystemThread(STATUS_SUCCESS);

		if (KO_ID[0] || KO_ID[1]) {
			PRTL_PROCESS_MODULES ModuleInfo = ExAllocatePool(NonPagedPool, 1024 * 1024);
			if (ModuleInfo)
			{
				if (NT_SUCCESS(ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, ModuleInfo, 1024 * 1024, NULL))) {
					for (ULONG i = 0; i < ModuleInfo->NumberOfModules; i++)
					{
						for (ULONG j = 0; j < arraysize(ForbiddenDrivers); j++) {
							UCHAR* str = ModuleInfo->Modules[i].FullPathName;
							ToLowerAll(str);
							if (strstr(str, ForbiddenDrivers[j]))
							{
								if (KO_ID[0]) KillProcess(KO_ID[0]);
								if (KO_ID[1]) KillProcess(KO_ID[1]);
								DebugMessage("Detected: %s", str);
							}
						}
					}
				}
				ExFreePool(ModuleInfo);
			}
		}

		KeDelayExecutionThread(KernelMode, FALSE, &delay);
	}
}

void ToLowerAll(char* str)
{
	for (ULONG i = 0; str[i] != '\0'; i++)
		str[i] = tolower(str[i]);
}