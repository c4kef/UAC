#include "..\funcs.h"
#include "..\log.h"

BOOL ScanSysThreads(PSYSTEM_MODULE_INFORMATION pModuleList)
{
	SleepThread(1000);
	for (ULONG thrd_id = 4; thrd_id < 0x30000; thrd_id += 4)
	{
		PETHREAD ThreadObj;

		if (!NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)(thrd_id), &ThreadObj)))
		{
			continue;
		}

		if (!PsIsSystemThread(ThreadObj) || ThreadObj == KeGetCurrentThread())//ignore system threads
		{
			continue;
		}

		uintptr_t start_addr;

		GetThreadStartAddress(ThreadObj, &start_addr);

		if (IsAddressOutsideModuleList(pModuleList, start_addr) || (start_addr && (memcmp((void*)start_addr, "\xFF\xE1", 2) == 0)))
		{
			DPRINT_LOG("(%s) Offending stream found: id = %u   address = 0x%X", __FUNCTION__, thrd_id, start_addr);
			return TRUE;
		}
	}
	return FALSE;
}