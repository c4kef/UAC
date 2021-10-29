#include "..\funcs.h"
#include "..\log.h"

BOOL ScanDispatchDrivers(PSYSTEM_MODULE_INFORMATION pModuleList)
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hDir;
	UNICODE_STRING str;
	OBJECT_ATTRIBUTES oa;
	RtlInitUnicodeString(&str, L"\\Driver");
	InitializeObjectAttributes(&oa, &str, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, (HANDLE)NULL, (PSECURITY_DESCRIPTOR)NULL);
	if (!NT_SUCCESS(status = ZwOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa))) {
		DPRINT_LOG("(%s) Failed to open \\Driver directory object, code: 0x%X", __FUNCTION__, status);
		return FALSE;
	}

	PVOID Obj;
	if (!NT_SUCCESS(status = ObReferenceObjectByHandle(hDir, DIRECTORY_QUERY, NULL, KernelMode, &Obj, NULL))) {
		DPRINT_LOG("(%s) ObReferenceObjectByHandle failed, code: 0x%X", __FUNCTION__, status);
		return FALSE;
	}
	NtClose(hDir);

	POBJECT_TYPE obj_type = ObGetObjectType(Obj);
	ObDereferenceObject(Obj);

	HANDLE h;
	if (!NT_SUCCESS(status = ObOpenObjectByName(&oa, obj_type, KernelMode, NULL, DIRECTORY_QUERY, NULL, &h))) {
		DPRINT_LOG("(%s) ObOpenObjectByName failed, code: 0x%X", __FUNCTION__, status);
		return FALSE;
	}

	POBJDIR_INFORMATION dir_info = (POBJDIR_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOL_TAG);
	ULONG    ulContext = 0;

	ULONG returned_bytes;
	_ZwQueryDirectoryObject zwQDO = FindModule(L"ZwQueryDirectoryObject");

	if (!zwQDO)
	{
		DPRINT_LOG("(%s) ZwQueryDirectoryObject not found.", __FUNCTION__);
		return FALSE;
	}

	while (NT_SUCCESS(zwQDO(h, dir_info, PAGE_SIZE, TRUE, FALSE, &ulContext, &returned_bytes))) 
	{
		PDRIVER_OBJECT pObj;
		wchar_t wsDriverName[100] = L"\\Driver\\";
		wcscat(wsDriverName, dir_info->ObjectName.Buffer);
		UNICODE_STRING ObjName;
		ObjName.Length = ObjName.MaximumLength = wcslen(wsDriverName) * 2;
		ObjName.Buffer = wsDriverName;

		if (NT_SUCCESS(ObReferenceObjectByName(&ObjName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&pObj))) {
			UNICODE_STRING path;
			wchar_t w_path[2048];
			UNICODE_STRING DriverName = pObj->DriverName;
			if (!NT_SUCCESS(IoQueryFullDriverPath(pObj, &path)))
			{
				RtlInitUnicodeString(&path, L"not found");
				DPRINT_LOG("(%s) [FLAG] %wZ driver has not found path", __FUNCTION__, DriverName);
			}
			else
			{
				swprintf(w_path, L"%wZ", path);
			}

			if (IsAddressOutsideModuleList(pModuleList, (uintptr_t)(pObj->MajorFunction[IRP_MJ_DEVICE_CONTROL])))
			{
				ObDereferenceObject(pObj);
				DPRINT_LOG("(%s) [DETECT] %wZ driver has spoofed driver dispatch", __FUNCTION__, DriverName);
				return TRUE;
			}

			if (IsAddressOutsideModuleList(pModuleList, (uintptr_t)pObj->DriverStart))
			{
				ObDereferenceObject(pObj);
				DPRINT_LOG("(%s) [DETECT] %wZ driver has spoofed DriverStart", __FUNCTION__, DriverName);
				return TRUE;
			}

			//flags detection
			uintptr_t dd = (uintptr_t)(pObj->MajorFunction[IRP_MJ_DEVICE_CONTROL]);
			if ((dd < (uintptr_t)pObj->DriverStart || dd >(uintptr_t)pObj->DriverStart + pObj->DriverSize))
			{
				ObDereferenceObject(pObj);
				if (!CheckSignedFile(w_path))
				{
					DPRINT_LOG("(%s) [FLAG] %wZ driver has spoofed driver dispatch, path = %wZ", __FUNCTION__, DriverName, path);
				}
				continue;
			}

			if (IsAddressOutsideModuleList(pModuleList, (uintptr_t)(pObj->FastIoDispatch)))
			{
				ObDereferenceObject(pObj);
				if (!CheckSignedFile(w_path))
				{
					DPRINT_LOG("(%s) [FLAG] %wZ driver has spoofed FastIoDispatch", __FUNCTION__, DriverName);
				}
				continue;
			}
			ObDereferenceObject(pObj);
		}
	}
	ZwClose(h);
	return FALSE;
}