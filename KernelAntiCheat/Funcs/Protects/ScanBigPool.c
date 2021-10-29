#include "..\funcs.h"
#include "..\log.h"

BOOL ScanBigPool()
{
	ULONG len = 4 * 1024 * 1024;
	PVOID mem = ExAllocatePoolWithTag(NonPagedPool, len, POOL_TAG);
	NTSTATUS status = STATUS_SUCCESS;
	if (NT_SUCCESS(status = ZwQuerySystemInformation(SystemBigPoolInformation, mem, len, &len))) {
		PSYSTEM_BIGPOOL_INFORMATION pBuf = (PSYSTEM_BIGPOOL_INFORMATION)(mem);
		for (ULONG i = 0; i < pBuf->Count; i++) {
			__try {
				if (pBuf->AllocatedInfo[i].TagUlong == 'SldT') {
					DPRINT_LOG("(%s) [FLAG] TdlS pooltag detected", __FUNCTION__);
					PVOID page = MmMapIoSpaceEx(MmGetPhysicalAddress((void*)pBuf->AllocatedInfo[i].VirtualAddress), PAGE_SIZE, PAGE_READWRITE);
					if (page)
					{
						PULONG hash = *(PULONG)((uintptr_t)page + 0x184);
						if (hash == 0x0B024BC8B48 || hash == 0x0C8931AEB)
						{
							MmUnmapIoSpace(page, PAGE_SIZE);
							DPRINT_LOG("(%s) [DETECT] 0x0B024BC8B48 found at pool + 0x184", __FUNCTION__);
							return TRUE;
						}

						MmUnmapIoSpace(page, PAGE_SIZE);
					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DPRINT_LOG("(%s) Access Violation was raised.", __FUNCTION__);
			}
		}
	}
	else
	{
		DPRINT_LOG("(%s) Failed to get pool information! Code: 0x%x", __FUNCTION__, status);
	}

	ExFreePoolWithTag(mem, POOL_TAG);
	return FALSE;
}