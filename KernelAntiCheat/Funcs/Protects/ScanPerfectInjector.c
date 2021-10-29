#include "..\funcs.h"
#include "..\log.h"
BOOL ScanPerfectInjector()
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING phys_mem_str;
	OBJECT_ATTRIBUTES oaAttributes;
	RtlInitUnicodeString(&phys_mem_str, L"\\Device\\PhysicalMemory");
	InitializeObjectAttributes(&oaAttributes, &phys_mem_str, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, (HANDLE)NULL, (PSECURITY_DESCRIPTOR)NULL);
	HANDLE hPhysMem;
	if (!NT_SUCCESS(status = ZwOpenSection(&hPhysMem, SECTION_ALL_ACCESS, &oaAttributes))) {
		DPRINT_LOG("(%s) Failed to open phys mem section, code: 0x%X", __FUNCTION__, status);
		return FALSE;
	}

	PVOID PhysicalMemoryBegin = NULL;

	PPHYSICAL_MEMORY_RANGE Range = MmGetPhysicalMemoryRanges();
	DWORD64 PhysicalMemorySize = 0;

	while (Range->NumberOfBytes.QuadPart)
	{
		PhysicalMemorySize = max(PhysicalMemorySize, Range->BaseAddress.QuadPart + Range->NumberOfBytes.QuadPart);
		Range++;
	}

	if (!NT_SUCCESS(status = ZwMapViewOfSection(hPhysMem, ZwCurrentProcess(), &PhysicalMemoryBegin, NULL, NULL, NULL, &PhysicalMemorySize, ViewUnmap, NULL, PAGE_READWRITE))) {
		DPRINT_LOG("(%s) ZwMapViewOfSection failed, code: 0x%X", __FUNCTION__, status);
		ZwClose(hPhysMem);
		return FALSE;
	}

	PSYSTEM_PROCESS_INFO processes = GetProcList();
	if (!processes) {
		DPRINT_LOG("(%s) Unable to get process list.", __FUNCTION__);
		ZwUnmapViewOfSection(ZwCurrentProcess(), PhysicalMemoryBegin);
		ZwClose(hPhysMem);
		return FALSE;
	}

	PSYSTEM_PROCESS_INFO walk = processes;
	while (walk->NextEntryOffset)
	{
		KAPC_STATE apcState;

		PEPROCESS process = NULL;
		if (walk->UniqueProcessId != NULL)
		{
			if (NT_SUCCESS(PsLookupProcessByProcessId(walk->UniqueProcessId, &process))) {

				__try {
					KeStackAttachProcess(process, &apcState);
					PVOID cr3 = __readcr3();
					KeUnstackDetachProcess(&apcState);

					PTE_CR3 Cr3 = { cr3 };

					VIRT_ADDR system_range_start = { (uintptr_t)MmSystemRangeStart };

					for (int pml4_index = system_range_start.pml4_index; pml4_index < 512; pml4_index++)
					{
						uint64_t pml4_addr = PFN_TO_PAGE(Cr3.pml4_p) + sizeof(PML4E) * pml4_index;
						if (pml4_addr > PhysicalMemorySize)
						{
							continue;
						}
						PML4E* pml4 = (PML4E*)((uintptr_t)PhysicalMemoryBegin + pml4_addr);
						if (pml4->present && pml4->user) {
							for (int pdpt_index = system_range_start.pdpt_index; pdpt_index < 512; pdpt_index++) {

								uintptr_t pdpte_addr = PFN_TO_PAGE(pml4->pdpt_p) + sizeof(PDPTE) * pdpt_index;
								if (pdpte_addr > PhysicalMemorySize)
								{
									continue;
								}

								PDPTE* pdpte = (PDPTE*)((uintptr_t)PhysicalMemoryBegin + pdpte_addr);
								if (!pdpte->present || !pdpte->user)
								{
									continue;
								}

								DPRINT_LOG("(%s) [DETECT] kernelmode memory mapped to usermode: %wZ", __FUNCTION__, walk->ImageName);

								return TRUE;
							}
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					DPRINT_LOG("(%s) unexpected AV in detect PI.", __FUNCTION__);
				}
				ObDereferenceObject(process);
			}
			else
			{
				DPRINT_LOG("(%s) Unable to lookup _EPROCESS from PID %d.", __FUNCTION__, (ULONG)walk->UniqueProcessId);
			}
		}
		walk = (PSYSTEM_PROCESS_INFO)((uintptr_t)walk + walk->NextEntryOffset);
	}

	ExFreePoolWithTag(processes, POOL_TAG);
	ZwUnmapViewOfSection(ZwCurrentProcess(), PhysicalMemoryBegin);
	ZwClose(hPhysMem);
}