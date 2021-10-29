#include "NativeEnums.h"
#include "NativeStructs.h"

typedef NTSTATUS(__fastcall* _ZwQueryDirectoryObject)
(
    IN HANDLE DirectoryHandle,
    OUT PVOID Buffer,
    IN ULONG BufferLength,
    IN BOOLEAN ReturnSingleEntry,
    IN BOOLEAN RestartScan,
    IN OUT PULONG Context,
    OUT PULONG ReturnLength OPTIONAL
);

typedef NTSTATUS(NTAPI* _KeSetAffinityThread)
(
    PKTHREAD pKThread,
    KAFFINITY cpuAffinityMask
);

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID               SystemInformation,
    IN ULONG                SystemInformationLength,
    OUT PULONG              ReturnLength OPTIONAL);

NTSYSAPI
NTSTATUS
NTAPI
MmCheckSystemImage(
    IN  HANDLE ImageFileHandle,
    IN  LOGICAL PurgeSection
);

RUNTIME_FUNCTION RtlLookupFunctionEntry(
    DWORD64               ControlPc,
    PDWORD64              ImageBase,
    PUNWIND_HISTORY_TABLE HistoryTable
);

NTSYSAPI VOID RtlUnwindEx(
    PVOID                 TargetFrame,
    PVOID                 TargetIp,
    PEXCEPTION_RECORD     ExceptionRecord,
    PVOID                 ReturnValue,
    PCONTEXT              ContextRecord,
    PUNWIND_HISTORY_TABLE HistoryTable
);

NTSYSAPI PEXCEPTION_ROUTINE RtlVirtualUnwind(
    PVOID                          HandlerType,
    DWORD64                        ImageBase,
    DWORD64                        ControlPc,
    PRUNTIME_FUNCTION              FunctionEntry,
    PCONTEXT                       ContextRecord,
    PVOID* HandlerData,
    PDWORD64                       EstablisherFrame,
    PKNONVOLATILE_CONTEXT_POINTERS ContextPointers
);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationThread(
    IN HANDLE               ThreadHandle,
    IN THREAD_INFORMATION_CLASS ThreadInformationClass,
    OUT PVOID               ThreadInformation,
    IN ULONG                ThreadInformationLength,
    OUT PULONG              ReturnLength OPTIONAL);

NTSTATUS ObReferenceObjectByName(PUNICODE_STRING objectName, ULONG attributes, PACCESS_STATE accessState, ACCESS_MASK desiredAccess, POBJECT_TYPE objectType, KPROCESSOR_MODE accessMode, PVOID parseContext, PVOID* object);

NTKERNELAPI
NTSTATUS
NTAPI
ObOpenObjectByName(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE PreviousMode,
    _In_opt_ PACCESS_STATE AccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_opt_ PVOID ParseContext,
    _Out_ PHANDLE Handle
);

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID Object
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

NTSYSAPI
NTSTATUS
NTAPI
ZwSetSystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN PVOID SystemInformation,
    IN ULONG SystemInformationLength
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
    IN  HANDLE ProcessHandle,
    IN  PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN  ULONG ProcessInformationLength,
    IN  PULONG ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

NTSTATUS
NTAPI
ZwCreateThreadEx(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList
);

NTSTATUS
NTAPI
ZwTerminateThread(
    IN HANDLE ThreadHandle,
    IN NTSTATUS ExitStatus
);



NTKERNELAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
    IN PEPROCESS FromProcess,
    IN PVOID FromAddress,
    IN PEPROCESS ToProcess,
    OUT PVOID ToAddress,
    IN SIZE_T BufferSize,
    IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T NumberOfBytesCopied
);

NTKERNELAPI
PPEB
NTAPI
PsGetProcessPeb(IN PEPROCESS Process);

NTKERNELAPI
PVOID
NTAPI
PsGetThreadTeb(IN PETHREAD Thread);

NTKERNELAPI
PVOID
NTAPI
PsGetProcessWow64Process(IN PEPROCESS Process);

NTKERNELAPI
PVOID
NTAPI
PsGetCurrentProcessWow64Process();

NTKERNELAPI
BOOLEAN
NTAPI
KeTestAlertThread(IN KPROCESSOR_MODE AlertMode);

NTKERNELAPI
BOOLEAN
NTAPI
PsIsProtectedProcess(IN PEPROCESS Process);

typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
    );

typedef VOID(NTAPI* PKKERNEL_ROUTINE)(
    PRKAPC Apc,
    PKNORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArgument1,
    PVOID* SystemArgument2
    );

typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(PRKAPC Apc);

NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
    IN PKAPC Apc,
    IN PKTHREAD Thread,
    IN KAPC_ENVIRONMENT ApcStateIndex,
    IN PKKERNEL_ROUTINE KernelRoutine,
    IN PKRUNDOWN_ROUTINE RundownRoutine,
    IN PKNORMAL_ROUTINE NormalRoutine,
    IN KPROCESSOR_MODE ApcMode,
    IN PVOID NormalContext
);

NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
    PKAPC Apc,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    KPRIORITY Increment
);

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(PVOID Base);

NTSYSAPI
PVOID
NTAPI
RtlImageDirectoryEntryToData(
    PVOID ImageBase,
    BOOLEAN MappedAsImage,
    USHORT DirectoryEntry,
    PULONG Size
);


NTKERNELAPI
VOID
FASTCALL
ExfUnblockPushLock(
    IN OUT PEX_PUSH_LOCK PushLock,
    IN OUT PVOID WaitBlock
);