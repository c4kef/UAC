#include <ntifs.h>
#include <windef.h>
#include <classpnp.h>
#include "..\Natives\Imports.h"
#include "..\Natives\Windows\ci.h"

#define DPRINT(message, ...) \
	DbgPrintEx(0, 0, "[UAC] - "); \
	DbgPrintEx(0, 0, message, __VA_ARGS__); \
	DbgPrintEx(0, 0, "\n");

#define DPRINT_STATUS(func_check, status) \
	DbgPrintEx(0, 0, "[UAC] - Scan "); \
	DbgPrintEx(0, 0, func_check); \
	DbgPrintEx(0, 0, ": "); \
	DbgPrintEx(0, 0, status ? "[DETECT]\n" : "[OK]\n"); \

#define POOL_TAG 'ek4C'
#define PAGE_MASK (~(PAGE_SIZE-1))

#define PFN_TO_PAGE(pfn) (pfn << PAGE_SHIFT)
#define PAGE_TO_PFN(pfn) (pfn >> PAGE_SHIFT)

extern POBJECT_TYPE* IoDriverObjectType;

char* JoinText(char* format, ...);

PVOID GetModuleBaseAddress(PCHAR name);

PVOID GetKernelBase();

PVOID GetKernelBaseWithSize(ULONG* Size);

PVOID FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask);

BOOLEAN CheckMask(PCHAR base, PCHAR pattern, PCHAR mask);

PVOID FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask);

NTSTATUS LoadLibrary(PCWCHAR Filename, PVOID* ImageBase, PSIZE_T ViewSize);

NTSTATUS RtlOpenFile(PCWCHAR Filename, PHANDLE FileHandle);

NTSTATUS ScanSection(PCCHAR section, PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, PVOID* ppFound);

NTSTATUS SearchPattern(PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const VOID* base, ULONG_PTR size, PVOID* ppFound, int index);

PSYSTEM_HANDLE_INFORMATION GetHandleList();

PSYSTEM_PROCESS_INFO GetProcList();

PVOID GetProcAddress(ULONG_PTR DllBase, PCCH RoutineName);

VOID PrintModuleName(PSYSTEM_MODULE_INFORMATION pModuleList, uintptr_t addr);

PSYSTEM_MODULE_INFORMATION GetKernelModuleList();

PVOID FindModule(const wchar_t* NameModule);

EXTERN_C PVOID ResolveRelativeAddress( PVOID Instruction,  ULONG OffsetOffset,  ULONG InstructionSize);

VOID SleepThread(LONG milliseconds);

NTSTATUS GetThreadStartAddress(PETHREAD ThreadObj, uintptr_t* pStartAddr);

BOOL IsAddressOutsideModuleList(PSYSTEM_MODULE_INFORMATION pModuleList, uint64_t* addr);

PSYSTEM_MODULE FindModuleInList(char* imageName, PSYSTEM_MODULE_INFORMATION pModuleList);

BOOL CheckSignedFile(PWCHAR filePath);