#pragma once
#include "RAIIUtilites.h"

HANDLE OpenFileReadHandleGuard(PCUNICODE_STRING imageFileName)
{
    HANDLE _handle;
    IO_STATUS_BLOCK ioStatusBlock = { 0 };
    OBJECT_ATTRIBUTES  objAttr = { 0 };
    InitializeObjectAttributes(
        &objAttr,
        (PUNICODE_STRING)(imageFileName),
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    const NTSTATUS openFileRet = ZwOpenFile(
        &_handle,
        SYNCHRONIZE | FILE_READ_DATA, // ACCESS_MASK, we use SYNCHRONIZE because we might need to wait on the handle in order to wait for the file to be read
        &objAttr,
        &ioStatusBlock,
        FILE_SHARE_READ,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT // FILE_SYNCHRONOUS_IO_NONALERT so that zwReadfile will pend for us until reading is done
    );

    if (!NT_SUCCESS(openFileRet))
    {
        KdPrint(("failed to open file - openFileRet = %d\n", openFileRet));
        return NULL;
    }

    if (ioStatusBlock.Status != STATUS_SUCCESS || _handle == NULL)
    {
        KdPrint(("ioStatusBlock.Status != STATUS_SUCCESS, or _handle is null\n"));
        return NULL;
    }

    return _handle;
}
HANDLE CreateSectionHandleGuard(HANDLE fileHandle)
{
    HANDLE _handle;
    OBJECT_ATTRIBUTES objectAttributes = { 0 };
    InitializeObjectAttributes(
        &objectAttributes,
        NULL,
        OBJ_KERNEL_HANDLE, // to make sure user mode cannot access this handle
        NULL,
        NULL);

    const NTSTATUS createSectionRet = ZwCreateSection(
        &_handle,
        SECTION_MAP_READ,
        &objectAttributes,
        NULL, // maximum size - use the file size, in order to map the entire file
        PAGE_READONLY,
        SEC_COMMIT, // map as commit and not as SEC_IMAGE, because SEC_IMAGE will not map things which are not needed for the PE - such as resources and certificates
        fileHandle
    );

    if (!NT_SUCCESS(createSectionRet))
    {
        KdPrint(("failed to create section - ZwCreateSection returned %x\n", createSectionRet));
        return NULL;
    }

    return _handle;
}
PVOID OpenSectionObjectGuard(HANDLE sectionHandle)
{
    PVOID _object;
    const NTSTATUS ret = ObReferenceObjectByHandle(
        sectionHandle,
        SECTION_MAP_READ,
        NULL,
        KernelMode,
        &_object,
        NULL
    );

    if (!NT_SUCCESS(ret))
    {
        KdPrint(("ObReferenceObjectByHandle failed -  returned %x\n", ret));
        return NULL;
    }

    return _object;
}
VOID CloseSectionObjectGuard(PVOID _object)
{
    if (_object != NULL)
    {
        ObfDereferenceObject(_object);
    }
}
PVOID MmMapSectionViewGuard(PVOID sectionObject, SIZE_T* _viewSizeGet)
{
    PVOID _baseAddrOfView;
    SIZE_T _viewSize = 0;
    const NTSTATUS ret = MmMapViewInSystemSpace(
        sectionObject,
        &_baseAddrOfView,
        &_viewSize
    );

    if (!NT_SUCCESS(ret))
    {
        KdPrint(("MmMapViewInSystemSpace failed -  returned %x\n", ret));
        return 0;
    }
    *_viewSizeGet = _viewSize;
    return _baseAddrOfView;
}
VOID MmUnmapSectionViewGuard(PVOID _baseAddrOfView)
{
    if (_baseAddrOfView != NULL)
    {
        MmUnmapViewInSystemSpace(_baseAddrOfView);
    }
}
VOID FreePolicyInfoGuard(PolicyInfo _policyInfo)
{
    CiFreePolicyInfo(&_policyInfo);
}