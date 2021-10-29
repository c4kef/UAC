#include "..\funcs.h"
#include "..\log.h"

BOOL anomaly_check(MEMORY_BASIC_INFORMATION memory_information)
{
	// REPORT ANY EXECUTABLE PAGE OUTSIDE OF KNOWN MODULES
	if (memory_information.Type == MEM_PRIVATE || memory_information.Type == MEM_MAPPED)
	{
		if (((uint64_t)memory_information.BaseAddress & 0xFF0000000000) != 0x7F0000000000 && // UPPER EQUALS 0x7F
			((uint64_t)memory_information.BaseAddress & 0xFFF000000000) != 0x7F000000000 &&  // UPPER EQUALS 0x7F0
			((uint64_t)memory_information.BaseAddress & 0xFFFFF0000000) != 0x70000000 && // UPPER EQUALS 0x70000
			(uint64_t)memory_information.BaseAddress != 0x3E0000)
		{
			DPRINT("DETECT Anomaly");
			return TRUE;
		}
	}
	return FALSE;
}

BOOL CheckSSDT(PSYSTEM_MODULE_INFORMATION modules)
{
	const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
	const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);

	NTSTATUS status = STATUS_SUCCESS;
	PSYSTEM_MODULE kernel_module = FindModuleInList("ntoskrnl.exe", modules);

	if (!kernel_module)
	{
		DPRINT_LOG("(%s) not found kernelmodule!", __FUNCTION__);
		return FALSE;
	} 

	uint64_t kernel_start = kernel_module->ImageBase;
	uint64_t kernel_end = (uint64_t)kernel_module->ImageBase + kernel_module->ImageSize - 1;

	for (ULONG KiSSSOffset = 0; KiSSSOffset < kernel_module->ImageSize - signatureSize; KiSSSOffset++)
	{
		if (RtlCompareMemory(((unsigned char*)kernel_start + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
		{
			uint64_t address = (uint64_t)((uint64_t)kernel_start + KiSSSOffset + signatureSize);
			LONG relativeOffset = 0;
			if ((*(unsigned char*)address == 0x4c) && (*(unsigned char*)(address + 1) == 0x8d) && (*(unsigned char*)(address + 2) == 0x15))
			{
				relativeOffset = *(LONG*)(address + 3);
			}

			if (relativeOffset == 0)
			{
				DPRINT_LOG("(%s) relativeOffset not found.", __FUNCTION__);
				return FALSE;
			}

			SSDT* pServiceDescriptorTable = (SSDT*)(address + relativeOffset + 7);

			DWORD* kist = pServiceDescriptorTable->KiServiceTable;
			DWORD num_sys_calls = pServiceDescriptorTable->nSystemCalls;

			for (ULONG ulServiceIndex = 0; ulServiceIndex < num_sys_calls; ulServiceIndex++, kist++)
			{
				if (IsAddressOutsideModuleList(modules, kist))
				{
					DPRINT_LOG("(%s) SSDT hook detect by address: %p", __FUNCTION__, kist);
					return TRUE;
				}
			}
		}
	}

	if (IsAddressOutsideModuleList(modules, kernel_start))
	{
		DPRINT("(%s)_1 Kernel detected: %p", __FUNCTION__, (uint64_t*)kernel_start);
	}

	for (uint64_t* kernel = kernel_module->ImageBase; kernel <= kernel_end; kernel++)
	{
		if (IsAddressOutsideModuleList(modules, kernel))
		{
			DPRINT("(%s)_2 Kernel detected: %p", __FUNCTION__, kernel);
		}
	}
	/*MEMORY_BASIC_INFORMATION  memory_information;
	LONG return_length;
	for (uint64_t current_address = kernel_module->ImageBase;
		NtQueryVirtualMemory(PsGetCurrentProcess(), current_address, 0, &memory_information, 0x30, &return_length) >= 0;
		current_address = (uint64_t)memory_information.BaseAddress + memory_information.RegionSize)
	{

		BOOL executable_memory =
			memory_information.State == MEM_COMMIT &&
			(memory_information.Protect == PAGE_EXECUTE ||
				memory_information.Protect == PAGE_EXECUTE_READ ||
				memory_information.Protect == PAGE_EXECUTE_READWRITE);

			BOOL unknown_whitelist =
			memory_information.Protect != PAGE_EXECUTE_READWRITE ||
			memory_information.RegionSize != 100000000;

			if (!executable_memory || !unknown_whitelist)
				continue;

			anomaly_check(memory_information);
	}*/

	return FALSE;
}