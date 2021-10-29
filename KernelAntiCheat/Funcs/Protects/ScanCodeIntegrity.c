#include "..\funcs.h"
#include "..\log.h"
#include "..\..\Natives\Hde\hde64.h"

HANDLE FileHandle;

LONG FindEntryCiOptions( PVOID MappedBase,  ULONG_PTR KernelBase,  PULONG_PTR gCiOptionsAddress)
{
	*gCiOptionsAddress = 0;

	ULONG i;
	LONG Relative = 0;
	hde64s hs;

	const PUCHAR CiInitialize = (GetProcAddress((ULONG_PTR)(MappedBase), "CiInitialize"));
	if (!CiInitialize)
		return 0;

	i = 0;
	ULONG j = 0;
	do
	{
		if (CiInitialize[i] == 0xE8)
			j++;

		if (j > 1)
		{
			Relative = *(PLONG)(CiInitialize + i + 1);
			break;
		}

		hde64_disasm(CiInitialize + i, &hs);
		if (hs.flags & F_ERROR)
			break;
		i += hs.len;

	} while (i < 256);

	const PUCHAR CipInitialize = CiInitialize + i + 5 + Relative;
	i = 0;
	do
	{
		if (*(PUSHORT)(CipInitialize + i) == 0x0d89)
		{
			Relative = *(PLONG)(CipInitialize + i + 2);
			break;
		}
		hde64_disasm(CipInitialize + i, &hs);
		if (hs.flags & F_ERROR)
			break;
		i += hs.len;

	} while (i < 256);

	const PUCHAR MappedCiOptions = CipInitialize + i + 6 + Relative;

	*gCiOptionsAddress = KernelBase + MappedCiOptions - (PUCHAR)(MappedBase);

	return Relative;
}

BOOL CheckDSEHack()
{
	PVOID CiOptionsAddress = 0;
	PVOID MappedBase = 0;
	SIZE_T ViewSize = 0;
	NTSTATUS Status = LoadLibrary(L"\\??\\C:\\Windows\\System32\\ci.dll", &MappedBase, &ViewSize);
	if (!NT_SUCCESS(Status))
	{
		DPRINT_LOG("(%s) Failed to map: 0x%X", __FUNCTION__, Status);
		return FALSE;
	}

	ULONG_PTR CiDllBase = GetModuleBaseAddress("CI.dll");
	if (!CiDllBase)
	{
		ZwUnmapViewOfSection(NtCurrentProcess(), MappedBase);
		DPRINT_LOG("(%s) CI.dll not found in kernel space!", __FUNCTION__);
		return FALSE;
	}

	ULONG_PTR gCiOptionsAddress;

	const LONG Relative = FindEntryCiOptions(MappedBase, CiDllBase, &gCiOptionsAddress);
	if (Relative != 0)
	{
		CiOptionsAddress = (PVOID)(gCiOptionsAddress);
		Status = STATUS_SUCCESS;
	}
	else
	{
		DPRINT_LOG("(%s) entry to CI!CiOptions not found!", __FUNCTION__);
		Status = STATUS_NOT_FOUND;
	}

	ZwUnmapViewOfSection(NtCurrentProcess(), MappedBase);

	int CiOptionsValue = 0x6;
	if (NT_SUCCESS(Status))
	{
		CiOptionsValue = *(int*)CiOptionsAddress;
	}

	return CiOptionsValue != 0x6;
}

BOOL CheckTestMode()
{
	SYSTEM_CODEINTEGRITY_INFORMATION sci = { 0 };
	ULONG dwcbSz = 0;
	sci.Length = sizeof(sci);
	NtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), &dwcbSz);
	return sci.CodeIntegrityOptions != CODEINTEGRITY_OPTION_ENABLED;
}

BOOL ScanCodeIntegrity() 
{
	BOOL testMode = CheckTestMode();
	BOOL dseCheck = CheckDSEHack();

	if (testMode)
	{
		DPRINT_LOG("(%s) [DETECT] enabled test mode", __FUNCTION__);
	}

	if (dseCheck)
	{
		DPRINT_LOG("(%s) [DETECT] u are using DSE hacks", __FUNCTION__);
	}

	return dseCheck || testMode;
}