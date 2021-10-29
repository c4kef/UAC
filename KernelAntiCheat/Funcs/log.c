#include "log.h"
#include "utils.h"
#include <Ntstrsafe.h>

HANDLE g_fHandle;
PCWSTR path_to_log = L"\\??\\C:\\uac_log.txt";
UNICODE_STRING     uniName;
IO_STATUS_BLOCK    ioStatusBlock;
OBJECT_ATTRIBUTES  objAttr;
NTSTATUS ntstatus = STATUS_SUCCESS;

VOID LogWrite(const char* text, ...)
{
    if (!g_fHandle)
    {
        DPRINT("(%s) g_fHandle is null (file not open or not created)", __FUNCTION__);
        return;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return;
    }

    char tmp[2048];
    va_list(args);
    va_start(args, text);
    vsprintf(tmp, text, args);

    char buffer[2048] = "UAC - ";
    strcat(buffer, tmp);
    strcat(buffer, "\n");

    size_t  cb;
    LARGE_INTEGER ByteOffset;

    ByteOffset.HighPart = -1;
    ByteOffset.LowPart = FILE_WRITE_TO_END_OF_FILE;

    if (NT_SUCCESS(ntstatus = RtlStringCbLengthA(buffer, sizeof(buffer), &cb)))
    {
        if (!NT_SUCCESS(ntstatus = ZwWriteFile(g_fHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, (ULONG)cb, &ByteOffset, NULL)))
        {
            DPRINT("(%s) Error write log, code: 0x%X", __FUNCTION__, ntstatus);
        }
    }
}

VOID LogClose()
{
    ZwClose(g_fHandle);
}

HANDLE LogOpen()
{
    RtlInitUnicodeString(&uniName, path_to_log);
    InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return NULL;
    }

    ZwDeleteFile(&objAttr);
    SleepThread(100);

    if (!NT_SUCCESS(ntstatus = ZwCreateFile(&g_fHandle, GENERIC_WRITE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
    {
        DPRINT("(%s) ZwCreateFile error 0x%X", __FUNCTION__, ntstatus);
        return NULL;
    }

    char buffer[2048] = { "\n_____________UAC Developer platform_____________\nVersion: 1.0\n" };
    size_t  cb;
    LARGE_INTEGER ByteOffset = { 0 };

    if (NT_SUCCESS(ntstatus = RtlStringCbLengthA(buffer, sizeof(buffer), &cb)))
    {
        ntstatus = ZwWriteFile(g_fHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, (ULONG)cb, &ByteOffset, NULL);
    }

    return g_fHandle;
}