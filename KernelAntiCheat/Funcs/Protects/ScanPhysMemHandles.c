#include "..\funcs.h"
#include "..\log.h"

BOOL ScanPhysMemHandles()
{
	PSYSTEM_HANDLE_INFORMATION handles = GetHandleList();
	if (!handles) {
		DPRINT_LOG("(%s) Unable to obtahandle list.", __FUNCTION__);
		return FALSE;
	}
	UNICODE_STRING phys_mem_str;
	OBJECT_ATTRIBUTES oaAttributes;
	RtlInitUnicodeString(&phys_mem_str, L"\\Device\\PhysicalMemory");
	InitializeObjectAttributes(&oaAttributes, &phys_mem_str, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, (HANDLE)NULL, (PSECURITY_DESCRIPTOR)NULL);
	HANDLE hPhysMem;
	NTSTATUS ntStatus = ZwOpenSection(&hPhysMem, SECTION_ALL_ACCESS, &oaAttributes);

	PVOID Object;
	if (!NT_SUCCESS(ObReferenceObjectByHandle(hPhysMem, 1, NULL, KernelMode, &Object, NULL))) {
		DPRINT_LOG("(%s) Unablle to get PhyiscalMemory object.", __FUNCTION__);
		ExFreePoolWithTag(handles, POOL_TAG);
		ZwClose(hPhysMem);
		return FALSE;
	}

	ZwClose(hPhysMem);

	__try {
		for (ULONG i = 0; i < handles->uCount; i++) {
			if (handles->Handles[i].uIdProcess == 4)
			{
				continue;
			}
			if (handles->Handles[i].pObject == Object) {
				if (!ObIsKernelHandle((HANDLE)handles->Handles[i].Handle)) {
					DPRINT_LOG("(%s) [DETECT] Usermode PhysicalMemory handle detected, pid = %d, access = 0x%x" __FUNCTION__, handles->Handles[i].uIdProcess, handles->Handles[i].GrantedAccess);
					return TRUE;
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DPRINT_LOG("(%s) Unexpected AV", __FUNCTION__);
	}

	ObDereferenceObject(Object);

	ExFreePoolWithTag(handles, POOL_TAG);
	return FALSE;
}