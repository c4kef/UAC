#include <ntifs.h>
#include "Funcs/funcs.h"
#include "Funcs/Hardware/HardwareInfo.h"
#include "Funcs/log.h"

VOID WorkThread()
{
	DPRINT_LOG("(%s) Thread is ready", __FUNCTION__);
	DPRINT("(!) Get hardware info...");
	PSYSTEM_BOOT_ENVIRONMENT_INFORMATION pBootInfo = GetBootUUID();
	if (pBootInfo)
	{
		DPRINT("Boot GUID: %08X-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X", pBootInfo->BootIdentifier.Data1, pBootInfo->BootIdentifier.Data2, pBootInfo->BootIdentifier.Data3, pBootInfo->BootIdentifier.Data4[0], pBootInfo->BootIdentifier.Data4[1], pBootInfo->BootIdentifier.Data4[2], pBootInfo->BootIdentifier.Data4[3], pBootInfo->BootIdentifier.Data4[4], pBootInfo->BootIdentifier.Data4[5], pBootInfo->BootIdentifier.Data4[6], pBootInfo->BootIdentifier.Data4[7]);
	}
	else
	{
		DPRINT("Boot GUID: not found");
	}

	DPRINT("(!) Start scaning...");
	DPRINT_LOG("(!) Start scaning...");

	PSYSTEM_MODULE_INFORMATION pModuleList = GetKernelModuleList();

	if (pModuleList)
	{
		DPRINT_LOG("Scan system threads...");
		DPRINT_STATUS("system threads", ScanSysThreads(pModuleList));
		DPRINT_LOG("End scan!");

		DPRINT_LOG("Scan dispatch drivers...");
		DPRINT_STATUS("dispatch drivers", ScanDispatchDrivers(pModuleList));
		DPRINT_LOG("End scan!");

		DPRINT_LOG("Scan ssdt hooks...");
		DPRINT_STATUS("ssdt hooks", CheckSSDT(pModuleList));
		DPRINT_LOG("End scan!");
	}
	else
	{
		DPRINT("(!) Failed to get module list.");
	}

	DPRINT_LOG("Scan big pool...");
	DPRINT_STATUS("big pool", ScanBigPool());
	DPRINT_LOG("End scan!");

	DPRINT_LOG("Scan PiDDB...");
	DPRINT_STATUS("history of modules (PiDDB)", ScanPIDDB());
	DPRINT_LOG("End scan!");

	DPRINT_LOG("Scan Hyper-V...");
	DPRINT_STATUS("Hyper-V", ScanHV());
	DPRINT_LOG("End scan!");

	DPRINT_LOG("Scan phys memory handles...");
	DPRINT_STATUS("physical memory handles", ScanPhysMemHandles());
	DPRINT_LOG("End scan!");

	DPRINT_LOG("Scan perfect injector...");
	DPRINT_STATUS("perfect injector", ScanPerfectInjector());
	DPRINT_LOG("End scan!");

	DPRINT_LOG("Scan code integrity...");
	DPRINT_STATUS("code integrity", ScanCodeIntegrity());
	DPRINT_LOG("End scan!");

	DPRINT("(!) Scaning end!");
	DPRINT_LOG("(!) Scaning end!");

	if (pModuleList)
		ExFreePoolWithTag(pModuleList, POOL_TAG);
}

VOID HookProcessesCreate(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);

	if (CreateInfo == NULL) return;

	if (CreateInfo->FileObject == NULL) return;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	PsSetCreateProcessNotifyRoutineEx(HookProcessesCreate, TRUE);
	LogClose();
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hThread;

	DriverObject->DriverUnload = DriverUnload;

	LogOpen();
	DbgPrintEx(0, 0, "_____________UAC Developer platform_____________\nVersion: 1.0\n");

	DPRINT("Driver is loaded!");
	DPRINT_LOG("(%s) Driver is loaded.", __FUNCTION__);

	if (!NT_SUCCESS(status = PsSetCreateProcessNotifyRoutineEx(HookProcessesCreate, FALSE)))
	{
		DPRINT("(%s) error setup hook to process, code: 0x%X", __FUNCTION__, status);
		LogClose();
		return status;
	}
	
	if (NT_SUCCESS(status = PsCreateSystemThread(&hThread, STANDARD_RIGHTS_ALL, NULL, NULL, NULL, (PKSTART_ROUTINE)&WorkThread, NULL)))
	{
		ZwClose(hThread);
	}
	else
	{
		DPRINT("(%s) Failed to create check thread, code: 0x%X", __FUNCTION__, status);
		LogClose();
		return status;
	}

	return status;
}