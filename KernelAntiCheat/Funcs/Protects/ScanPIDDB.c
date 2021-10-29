#include "..\funcs.h"
#include "..\log.h"

UCHAR PiDDBLockPtr_sig[] = "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C";
UCHAR PiDDBCacheTablePtr_sig[] = "\x66\x03\xD2\x48\x8D\x0D";

BOOL LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
{
	NTSTATUS status = STATUS_SUCCESS;
	PVOID PiDDBLockPtr = NULL, PiDDBCacheTablePtr = NULL;
	if (!NT_SUCCESS(status = ScanSection("PAGE", PiDDBLockPtr_sig, 0, sizeof(PiDDBLockPtr_sig) - 1, (PVOID*)(&PiDDBLockPtr)))) {
		DPRINT_LOG("(%s) Unable to find PiDDBLockPtr sig, code: 0x%X", __FUNCTION__, status);
		return FALSE;
	}

	if (!NT_SUCCESS(status = ScanSection("PAGE", PiDDBCacheTablePtr_sig, 0, sizeof(PiDDBCacheTablePtr_sig) - 1, (PVOID*)(&PiDDBCacheTablePtr)))) {
		DPRINT_LOG("(%s) Unable to find PiDDBCacheTablePtr sig, code: 0x%X", __FUNCTION__, status);
		return FALSE;
	}

	PiDDBCacheTablePtr = (PVOID)((uintptr_t)PiDDBCacheTablePtr + 3);

	*lock = (PERESOURCE)(ResolveRelativeAddress(PiDDBLockPtr, 3, 7));
	*table = (PRTL_AVL_TABLE)(ResolveRelativeAddress(PiDDBCacheTablePtr, 3, 7));

	return TRUE;
}

BOOL ScanPIDDB()
{
	PERESOURCE PiDDBLock; PRTL_AVL_TABLE table;
	if (!LocatePiDDB(&PiDDBLock, &table))
	{
		DPRINT_LOG("(%s) Failed to find piddb!", __FUNCTION__);
		return FALSE;
	}
	ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);
	for (piddbcentry* p = (piddbcentry*)RtlEnumerateGenericTableAvl(table, TRUE);
		p != NULL;
		p = (piddbcentry*)RtlEnumerateGenericTableAvl(table, FALSE)) {
		if (p->TimeDateStamp == 0x5284eac3)//kdmapper
		{
			DPRINT_LOG("(%s) [DETECT] found using kdmapper", __FUNCTION__);
			return TRUE;
		}
		if (p->TimeDateStamp == 0x57CD1415)//drvmap
		{
			DPRINT_LOG("(%s) [DETECT] found using drvmap", __FUNCTION__);
			return TRUE;
		}
	}

	ExReleaseResourceLite(PiDDBLock);
	return FALSE;
}