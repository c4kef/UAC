#include "HardwareInfo.h"
#include "../../Natives/Imports.h"
#include "..\log.h"

PSYSTEM_BOOT_ENVIRONMENT_INFORMATION GetBootUUID()
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	neededSize = PAGE_SIZE;

	PSYSTEM_BOOT_ENVIRONMENT_INFORMATION pBootInfo;

	if (pBootInfo = (PSYSTEM_BOOT_ENVIRONMENT_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, neededSize, POOL_TAG)) {
		NTSTATUS r;
		if (NT_SUCCESS(r = ZwQuerySystemInformation(SystemBootEnvironmentInformation, pBootInfo, neededSize, 0))) 
		{
			return pBootInfo;
		}
		else
		{
			DPRINT_LOG("(%s) r = 0x%X", __FUNCTION__, r);
		}
	}
	return NULL;
}