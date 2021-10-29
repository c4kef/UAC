#include "log.h"
#include "utils.h"
#include <Ntstrsafe.h>

PVOID g_KernelBase;
ULONG g_KernelSize;

char* JoinText(char* format, ...)
{
    char buff[2048];
    va_list(args);
    va_start(args, format);
    vsprintf(buff, format, args);
    return buff;
}

PVOID GetModuleBaseAddress(PCHAR name)
{
    PVOID addr = 0;

    ULONG size = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
    if (STATUS_INFO_LENGTH_MISMATCH != status) {
        return addr;
    }

    PSYSTEM_MODULE_INFORMATION modules = ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG);
    if (!modules) {
        return addr;
    }

    if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, 0))) {
        ExFreePool(modules);
        return addr;
    }

    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
        SYSTEM_MODULE m = modules->Modules[i];

        if (strstr((PCHAR)m.FullPathName, name)) {
            addr = m.ImageBase;
            break;
        }
    }

    ExFreePool(modules);
    return addr;
}

PVOID GetKernelBase()
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;
    PRTL_PROCESS_MODULES pMods = NULL;
    PVOID checkPtr = NULL;
    UNICODE_STRING routineName;

    if (g_KernelBase != NULL)
    {
        return g_KernelBase;
    }

    RtlUnicodeStringInit(&routineName, L"NtOpenFile");

    checkPtr = MmGetSystemRoutineAddress(&routineName);
    if (checkPtr == NULL)
    {
        DPRINT_LOG("(%s) checkPtr is null!", __FUNCTION__);
        return NULL;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (bytes == 0)
    {
        DPRINT_LOG("(%s) Invalid SystemModuleInformation size", __FUNCTION__);
        return NULL;
    }

    pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, POOL_TAG);

    if (pMods)
    {
        RtlZeroMemory(pMods, bytes);
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

    if (NT_SUCCESS(status) && pMods)
    {
        PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

        for (ULONG i = 0; i < pMods->NumberOfModules; i++)
        {
            if (checkPtr >= pMod[i].ImageBase &&
                checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
            {
                g_KernelBase = pMod[i].ImageBase;
                break;
            }
        }
    }

    if (pMods)
    {
        ExFreePoolWithTag(pMods, POOL_TAG);
    }

    return g_KernelBase;
}

PVOID GetKernelBaseWithSize(ULONG* Size)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;
    PRTL_PROCESS_MODULES pMods = NULL;
    PVOID checkPtr = NULL;
    UNICODE_STRING routineName;

    if (g_KernelBase != NULL && g_KernelSize != NULL)
    {
        *Size = g_KernelSize;
        return g_KernelBase;
    }

    RtlUnicodeStringInit(&routineName, L"NtOpenFile");

    checkPtr = MmGetSystemRoutineAddress(&routineName);
    if (checkPtr == NULL)
    {
        DPRINT_LOG("(%s) checkPtr is null!", __FUNCTION__);
        return NULL;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (bytes == 0)
    {
        DPRINT_LOG("(%s) Invalid SystemModuleInformation size", __FUNCTION__);
        return NULL;
    }

    pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, POOL_TAG);

    if (pMods)
    {
        RtlZeroMemory(pMods, bytes);
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

    if (NT_SUCCESS(status) && pMods)
    {
        PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

        for (ULONG i = 0; i < pMods->NumberOfModules; i++)
        {
            if (checkPtr >= pMod[i].ImageBase && checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
            {
                g_KernelBase = pMod[i].ImageBase;
                g_KernelSize = pMod[i].ImageSize;
                *Size = g_KernelSize;
                break;
            }
        }
    }

    if (pMods)
    {
        ExFreePoolWithTag(pMods, POOL_TAG);
    }

    return g_KernelBase;
}

PVOID GetProcAddress(ULONG_PTR DllBase, PCCH RoutineName)
{
    const PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)(DllBase);
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    const PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(DllBase + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    const PIMAGE_DATA_DIRECTORY ImageDirectories = HEADER_FIELD(NtHeaders, DataDirectory);
    const ULONG ExportDirRva = ImageDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    const ULONG ExportDirSize = ImageDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    const PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(DllBase + ExportDirRva);
    const PULONG AddressOfFunctions = (PULONG)(DllBase + ExportDirectory->AddressOfFunctions);
    const PUSHORT AddressOfNameOrdinals = (PUSHORT)(DllBase + ExportDirectory->AddressOfNameOrdinals);
    const PULONG AddressOfNames = (PULONG)(DllBase + ExportDirectory->AddressOfNames);

    LONG Low = 0;
    LONG Middle = 0;
    LONG High = ExportDirectory->NumberOfNames - 1;

    while (High >= Low)
    {
        Middle = (Low + High) >> 1;
        const LONG Result = strcmp(RoutineName, (PCHAR)(DllBase + AddressOfNames[Middle]));
        if (Result < 0)
            High = Middle - 1;
        else if (Result > 0)
            Low = Middle + 1;
        else
            break;
    }

    if (High < Low || Middle >= (LONG)(ExportDirectory->NumberOfFunctions))
        return NULL;
    const ULONG FunctionRva = AddressOfFunctions[AddressOfNameOrdinals[Middle]];
    if (FunctionRva >= ExportDirRva && FunctionRva < ExportDirRva + ExportDirSize)
        return NULL;

    return (PVOID)(DllBase + FunctionRva);
}

BOOLEAN CheckMask(PCHAR base, PCHAR pattern, PCHAR mask) 
{
    for (; *mask; ++base, ++pattern, ++mask) {
        if (*mask == 'x' && *base != *pattern) {
            return FALSE;
        }
    }

    return TRUE;
}

PVOID FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask)
{
    length -= (DWORD)strlen(mask);
    for (DWORD i = 0; i <= length; ++i) {
        PVOID addr = &base[i];
        if (CheckMask(addr, pattern, mask)) {
            return addr;
        }
    }

    return 0;
}

PVOID FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask)
{
    PVOID match = 0;

    PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
    for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER section = &sections[i];
        if (*(PINT)section->Name == 'EGAP' || memcmp(section->Name, ".text", 5) == 0) {
            match = FindPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
            if (match) {
                break;
            }
        }
    }

    return match;
}

NTSTATUS SearchPattern(PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const VOID* base, ULONG_PTR size, PVOID* ppFound, int index)
{
    ASSERT(ppFound != NULL && pattern != NULL && base != NULL);

    if (ppFound == NULL || pattern == NULL || base == NULL)
    {
        DPRINT_LOG("(%s) One or more args is null", __FUNCTION__);
        return STATUS_ACCESS_DENIED;
    }
    int cIndex = 0;
    for (ULONG_PTR i = 0; i < size - len; i++)
    {
        BOOLEAN found = TRUE;
        for (ULONG_PTR j = 0; j < len; j++)
        {
            if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
            {
                found = FALSE;
                break;
            }
        }

        if (found != FALSE && cIndex++ == index)
        {
            *ppFound = (PUCHAR)base + i;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

NTSTATUS ScanSection(PCCHAR section, PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, PVOID* ppFound)
{
    if (ppFound == NULL)
    {
        DPRINT_LOG("(%s) ppFound is null", __FUNCTION__);
        return STATUS_ACCESS_DENIED;
    }

    PVOID base = GetKernelBase();
    if (base == NULL)
    {
        DPRINT_LOG("(%s) base is null", __FUNCTION__);
        return STATUS_ACCESS_DENIED;
    }

    PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
    if (!pHdr)
    {
        DPRINT_LOG("(%s) pHdr is null", __FUNCTION__);
        return STATUS_ACCESS_DENIED;
    }

    PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

    for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
    {
        ANSI_STRING s1, s2;
        RtlInitAnsiString(&s1, section);
        RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
        if (RtlCompareString(&s1, &s2, TRUE) == 0)
        {
            PVOID ptr = NULL;
            NTSTATUS status = SearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr, 0);
            if (NT_SUCCESS(status)) {
                *(PULONG64)ppFound = (ULONG_PTR)(ptr);
                return status;
            }
        }
    }
    return STATUS_NOT_FOUND;
}

PSYSTEM_HANDLE_INFORMATION GetHandleList()
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG neededSize = 0;

    neededSize = 8 * 1024 * 1024;

    PSYSTEM_HANDLE_INFORMATION pHandleList;

    if (pHandleList = (PSYSTEM_HANDLE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, neededSize, POOL_TAG)) {

        NTSTATUS r;
        if (NT_SUCCESS(r = ZwQuerySystemInformation(SystemHandleInformation, pHandleList, neededSize, 0)))
        {
            return pHandleList;
        }
        else
        {
            DPRINT_LOG("(%s) r = %x", __FUNCTION__, r);
        }
    }
    return NULL;
}

PSYSTEM_PROCESS_INFO GetProcList()
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG neededSize = 0;

    neededSize = 8 * 1024 * 1024;

    PSYSTEM_PROCESS_INFO pProcessList;

    if (pProcessList = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, neededSize, POOL_TAG)) {

        NTSTATUS r;
        if (NT_SUCCESS(r = ZwQuerySystemInformation(SystemProcessInformation, pProcessList, neededSize, 0)))
        {
            return pProcessList;
        }
        else 
        {
            DPRINT_LOG("(%s) r = 0x%X", __FUNCTION__, r);
        }
    }
    return NULL;

}

PSYSTEM_MODULE_INFORMATION GetKernelModuleList()
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG neededSize = 0;

    ZwQuerySystemInformation(
        SystemModuleInformation,
        &neededSize,
        0,
        &neededSize
    );

    PSYSTEM_MODULE_INFORMATION pModuleList;

    pModuleList = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, neededSize, POOL_TAG);
    if (pModuleList == NULL)
    {
        return FALSE;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation,
        pModuleList,
        neededSize,
        0
    );

    return pModuleList;
}

VOID PrintModuleName(PSYSTEM_MODULE_INFORMATION pModuleList, uintptr_t addr)
{
    if (addr == NULL)
        return;
    __try {
        for (ULONG i = 0; i < pModuleList->NumberOfModules; i++)
        {
            if (addr >= (uintptr_t)(pModuleList->Modules[i].ImageBase) && addr <
                (uintptr_t)(pModuleList->Modules[i].ImageBase) + pModuleList->Modules[i].ImageSize) {
                USHORT name_offset = pModuleList->Modules[i].OffsetToFileName;
                if (name_offset > 256)
                    continue;
                DPRINT_LOG("(%s) module: %s", __FUNCTION__, &pModuleList->Modules[i].FullPathName[name_offset]);
                return;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DPRINT_LOG("(%s) Access Violation was raised.", __FUNCTION__);
    }
    DPRINT_LOG("(%s) Module: <unknown>", __FUNCTION__);
}

BOOL IsAddressOutsideModuleList(PSYSTEM_MODULE_INFORMATION pModuleList, uint64_t* addr)
{
    if (addr == NULL)
        return FALSE;
    __try {
        for (ULONG i = 0; i < pModuleList->NumberOfModules; i++)
        {
            if (addr >= (uint64_t*)(pModuleList->Modules[i].ImageBase) && addr < (uint64_t*)((uint64_t*)pModuleList->Modules[i].ImageBase + pModuleList->Modules[i].ImageSize - 1)) 
            {
                return FALSE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DPRINT_LOG("(%s) Access Violation was raised!", __FUNCTION__);
    }
    return TRUE;
}

PSYSTEM_MODULE FindModuleInList(char* imageName, PSYSTEM_MODULE_INFORMATION pModuleList)
{
    for (int i = 0; i < pModuleList->NumberOfModules; i++)
    {
        if (strstr(pModuleList->Modules[i].FullPathName, imageName) != NULL)
        {
            return &(pModuleList->Modules[i]);
        }
    }
    return NULL;
}

NTSTATUS GetThreadStartAddress(PETHREAD ThreadObj, uintptr_t* pStartAddr)
{
    *pStartAddr = NULL;
    HANDLE hThread;
    NTSTATUS status = STATUS_SUCCESS;
    if (!NT_SUCCESS(status = ObOpenObjectByPointer(ThreadObj, OBJ_KERNEL_HANDLE, NULL, GENERIC_READ, *PsThreadType, KernelMode, &hThread))) {
        DPRINT_LOG("(%s) ObOpenObjectByPointer failed, code: 0x%p", __FUNCTION__, status);
        return status;
    }

    uintptr_t start_addr;
    ULONG returned_bytes;

    if (!NT_SUCCESS(status = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &start_addr, sizeof(start_addr), &returned_bytes))) {
        DPRINT_LOG("(%s) NtQueryInformationThread failed, code: 0x%p", __FUNCTION__, status);
        NtClose(hThread);
        return status;
    }

    if (MmIsAddressValid((void*)start_addr))
        *pStartAddr = start_addr;

    NtClose(hThread);

    return status;
}

PVOID FindModule(const wchar_t* NameModule)
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, NameModule);
    return MmGetSystemRoutineAddress(&routineName);
}

NTSTATUS RtlOpenFile(PCWCHAR Filename, PHANDLE FileHandle)
{
    IO_STATUS_BLOCK    ioStatusBlock;
    OBJECT_ATTRIBUTES  objAttr;
    HANDLE t_fHandle;
    UNICODE_STRING uniName;
    RtlInitUnicodeString(&uniName, Filename);

    InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS ntstatus = NtCreateFile(&t_fHandle, FILE_GENERIC_READ | SYNCHRONIZE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    *FileHandle = t_fHandle;
    return ntstatus;
}

NTSTATUS LoadLibrary(PCWCHAR Filename, PVOID* ImageBase, PSIZE_T ViewSize)
{
    *ImageBase = NULL;
    *ViewSize = 0;

    HANDLE t_fHandle;

    NTSTATUS Status = RtlOpenFile(Filename, &t_fHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT_LOG("(%s) error NtCreateFile: 0x%X", __FUNCTION__, Status);
        return Status;
    }

    HANDLE SectionHandle;
    Status = NtCreateSection(&SectionHandle, STANDARD_RIGHTS_REQUIRED | SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_IMAGE, t_fHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT_LOG("(%s) error NtCreateSection: 0x%X", __FUNCTION__, Status);
        NtClose(t_fHandle);
        return Status;
    }

    Status = ZwMapViewOfSection(SectionHandle, NtCurrentProcess(), ImageBase, 0, 0, NULL, ViewSize, ViewUnmap, 0, PAGE_READONLY);

    if (Status == STATUS_IMAGE_NOT_AT_BASE)
    {
        Status = STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(Status))
    {
        DPRINT_LOG("(%s) error NtMapViewOfSection: 0x%X", __FUNCTION__, Status);
    }

    NtClose(SectionHandle);
    NtClose(t_fHandle);

    return Status;
}

EXTERN_C PVOID ResolveRelativeAddress( PVOID Instruction,  ULONG OffsetOffset,  ULONG InstructionSize)
{
    ULONG_PTR Instr = (ULONG_PTR)Instruction;
    LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
    PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

    return ResolvedAddr;
}

VOID SleepThread(LONG milliseconds)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -(10000ll * milliseconds);

    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

BOOL CheckSignedFile(PWCHAR filePath)
{
    HANDLE FileHandle;
    PFILE_OBJECT fileObject;
    NTSTATUS status = STATUS_SUCCESS;
    NT_ASSERT(KeGetCurrentIrql() < DISPATCH_LEVEL);
    
    if (!NT_SUCCESS(status = RtlOpenFile(filePath, &FileHandle)))
    {
        DPRINT_LOG("(%s) error open file, error code: 0x%X   path = %ws", __FUNCTION__, status, filePath);
        return FALSE;
    }
    
    if (!NT_SUCCESS(status = ObReferenceObjectByHandle(FileHandle, NULL, NULL, KernelMode, &fileObject, NULL))) 
    {
        DPRINT_LOG("(%s) error open handle, error code: 0x%X", __FUNCTION__, status);
        ZwClose(FileHandle);
        return FALSE;
    }

    PolicyInfo signerPolicyInfo;
    PolicyInfo timestampingAuthorityPolicyInfo;
    LARGE_INTEGER signingTime = { 0 };
    int digestSize = 64;
    int digestIdentifier = 0;
    BYTE digestBuffer[64] = { 0 };

    status = CiValidateFileObject(fileObject, 0, 0, &signerPolicyInfo, &timestampingAuthorityPolicyInfo, &signingTime, digestBuffer, &digestSize, &digestIdentifier);

    ZwClose(FileHandle);
    ObReferenceObject(fileObject);

    return NT_SUCCESS(status);
}