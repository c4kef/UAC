#pragma once

#include "PEStructs.h"
#include "stdint.h"

#define MAKEINTRESOURCEW(i) ((PWCH)((ULONG_PTR)((USHORT)(i))))

#pragma pack(push, 4)
#define POBJECT PVOID
#define GDI_BATCH_BUFFER_SIZE 310

typedef struct SSDTStruct
{
    DWORD* KiServiceTable;		//SSDT entry 
    DWORD* CounterBaseTable;
    DWORD nSystemCalls;			//nElements SSDT
    DWORD* KiArgumentTable;
} SSDT;


typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG  Length;
    ULONG  CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _GDI_TEB_BATCH
{
    ULONG Offset;
    ULONG_PTR HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _ACTIVATION_CONTEXT_STACK
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _TEB
{
    NT_TIB NtTib;

    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;

    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _WIN64
    PVOID SystemReserved1[30];
#else
    PVOID SystemReserved1[26];
#endif
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderReserved[11];
    ULONG ProxiedProcessId;
    ACTIVATION_CONTEXT_STACK ActivationStack;

    UCHAR WorkingOnBehalfTicket[8];
    NTSTATUS ExceptionCode;

    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
    ULONG_PTR InstrumentationCallbackSp;
    ULONG_PTR InstrumentationCallbackPreviousPc;
    ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _WIN64
    ULONG TxFsContext;
#endif
    BOOLEAN InstrumentationCallbackDisabled;
#ifndef _WIN64
    UCHAR SpareBytes[23];
    ULONG TxFsContext;
#endif
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[62];
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    NTSTATUS LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];

    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    LIST_ENTRY TlsLinks;

    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];

    ULONG HardErrorMode;
#ifdef _WIN64
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif
    GUID ActivityId;

    PVOID SubProcessTag;
    PVOID PerflibData;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;

    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        } s1;
    } u1;

    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR ReservedForCodeCoverage;
    PVOID ThreadPoolData;
    PVOID* TlsExpansionSlots;
#ifdef _WIN64
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
#endif
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    USHORT HeapVirtualAffinity;
    USHORT LowFragHeapDataSlot;
    HANDLE CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;

    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;

    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    } u2;
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SpareSameTebBits : 1;
        } s2;
    } u3;

    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    LONG WowTebOffset;
    PVOID ResourceRetValue;
    PVOID ReservedForWdf;
    ULONGLONG ReservedForCrt;
    GUID EffectiveContainerId;
} TEB, * PTEB;

typedef struct _RTLP_CURDIR_REF* PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U
{
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;

typedef struct _SYSTEM_HANDLE
{
    ULONG 	uIdProcess;
    UCHAR 	ObjectType;
    UCHAR 	Flags;
    USHORT 	Handle;
    POBJECT 	pObject;
    ACCESS_MASK 	GrantedAccess;
}SYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG			uCount;
    SYSTEM_HANDLE	Handles[ANYSIZE_ARRAY];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

#pragma pack(pop)

typedef struct _UNLOADED_DRIVERS {
    UNICODE_STRING Name;
    PVOID StartAddress;
    PVOID EndAddress;
    LARGE_INTEGER CurrentTime;
} UNLOADED_DRIVERS, * PUNLOADED_DRIVERS;

typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION_V1 {
    struct _GUID BootIdentifier;
    enum _FIRMWARE_TYPE FirmwareType;
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION_V1, * PSYSTEM_BOOT_ENVIRONMENT_INFORMATION_V1;

// Size=32
typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION {
    struct _GUID BootIdentifier;
    enum _FIRMWARE_TYPE FirmwareType;
    unsigned __int64 BootFlags;
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, * PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
    union {
        uintptr_t VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };
    ULONG_PTR SizeInBytes;
    union {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
    ULONG Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

typedef struct PiDDBCacheEntry
{
    LIST_ENTRY		List;
    UNICODE_STRING	DriverName;
    ULONG			TimeDateStamp;
    NTSTATUS		LoadStatus;
    char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
} piddbcentry;

typedef union _cr0_t
{
    struct
    {
        uint64_t protection_enable : 1;
        uint64_t monitor_coprocessor : 1;
        uint64_t emulation : 1;
        uint64_t task_switched : 1;
        uint64_t extension_type : 1;
        uint64_t numeric_error : 1;
        uint64_t reserved : 10;
        uint64_t write_protect : 1;
        uint64_t reserved_1 : 1;
        uint64_t alignment_mask : 1;
        uint64_t reserved_2 : 10;
        uint64_t not_write_through : 1;
        uint64_t cache_disable : 1;
        uint64_t paging : 1;
        uint64_t reserved_3 : 32;
    };

    uint64_t full;
} cr0_t;

typedef struct _OBJDIR_INFORMATION {
    UNICODE_STRING          ObjectName;
    UNICODE_STRING          ObjectTypeName;
    BYTE                    Data[1];
} OBJDIR_INFORMATION, * POBJDIR_INFORMATION;

typedef union PML4E_ {
    pte_uint64 value;
    struct {
        pte_uint64 present : 1;
        pte_uint64 rw : 1;
        pte_uint64 user : 1;
        pte_uint64 write_through : 1;
        pte_uint64 cache_disable : 1;
        pte_uint64 accessed : 1;
        pte_uint64 ignored_1 : 1;
        pte_uint64 reserved_1 : 1;
        pte_uint64 ignored_2 : 4;
        pte_uint64 pdpt_p : 40;
        pte_uint64 ignored_3 : 11;
        pte_uint64 xd : 1;
    };
} PML4E;

typedef union PDPTE_ {
    pte_uint64 value;
    struct {
        pte_uint64 present : 1;
        pte_uint64 rw : 1;
        pte_uint64 user : 1;
        pte_uint64 write_through : 1;
        pte_uint64 cache_disable : 1;
        pte_uint64 accessed : 1;
        pte_uint64 dirty : 1;
        pte_uint64 page_size : 1;
        pte_uint64 ignored_2 : 4;
        pte_uint64 pd_p : 40;
        pte_uint64 ignored_3 : 11;
        pte_uint64 xd : 1;
    };
} PDPTE;

typedef union CR3_ {
  pte_uint64 value;
  struct {
    pte_uint64 ignored_1     : 3;
    pte_uint64 write_through : 1;
    pte_uint64 cache_disable : 1;
    pte_uint64 ignored_2     : 7;
    pte_uint64 pml4_p        :40;
    pte_uint64 reserved      :12;
  };
} PTE_CR3;

typedef union VIRT_ADDR_ {
  pte_uint64 value;
  void *pointer;
  struct {
    pte_uint64 offset        : 12;
    pte_uint64 pt_index      :  9;
    pte_uint64 pd_index      :  9;
    pte_uint64 pdpt_index    :  9;
    pte_uint64 pml4_index    :  9;
    pte_uint64 reserved      : 16;
  };
} VIRT_ADDR;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS
{
    PULONGLONG dummy;
} KNONVOLATILE_CONTEXT_POINTERS, * PKNONVOLATILE_CONTEXT_POINTERS;

typedef struct _SYSTEM_MODULE {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG NumberOfModules;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE 
{
    PULONG_PTR ServiceTableBase;
    PULONG ServiceCounterTableBase;
    ULONG_PTR NumberOfServices;
    PUCHAR ParamTableBase;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, *PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

typedef union _PS_PROTECTION
{
    UCHAR Level;
    struct
    {
        int Type : 3;
        int Audit : 1;
        int Signer : 4;
    } Flags;
} PS_PROTECTION, *PPS_PROTECTION;

typedef union _KEXECUTE_OPTIONS
{
    struct
    {
        int ExecuteDisable : 1;                     // 0x01
        int ExecuteEnable : 1;                      // 0x02
        int DisableThunkEmulation : 1;              // 0x04
        int Permanent : 1;                          // 0x08
        int ExecuteDispatchEnable : 1;              // 0x10
        int ImageDispatchEnable : 1;                // 0x20
        int DisableExceptionChainValidation : 1;    // 0x40
        int Spare : 1;
    } Flags;

    UCHAR ExecuteOptions;
} KEXECUTE_OPTIONS, *PKEXECUTE_OPTIONS;

typedef struct _EPROCESS_FLAGS2
{
    unsigned int JobNotReallyActive : 1;
    unsigned int AccountingFolded : 1;
    unsigned int NewProcessReported : 1;
    unsigned int ExitProcessReported : 1;
    unsigned int ReportCommitChanges : 1;
    unsigned int LastReportMemory : 1;
    unsigned int ForceWakeCharge : 1;
    unsigned int CrossSessionCreate : 1;
    unsigned int NeedsHandleRundown : 1;
    unsigned int RefTraceEnabled : 1;
    unsigned int DisableDynamicCode : 1;
    unsigned int EmptyJobEvaluated : 1;
    unsigned int DefaultPagePriority : 3;
    unsigned int PrimaryTokenFrozen : 1;
    unsigned int ProcessVerifierTarget : 1;
    unsigned int StackRandomizationDisabled : 1;
    unsigned int AffinityPermanent : 1;
    unsigned int AffinityUpdateEnable : 1;
    unsigned int PropagateNode : 1;
    unsigned int ExplicitAffinity : 1;
    unsigned int ProcessExecutionState : 2;
    unsigned int DisallowStrippedImages : 1;
    unsigned int HighEntropyASLREnabled : 1;
    unsigned int ExtensionPointDisable : 1;
    unsigned int ForceRelocateImages : 1;
    unsigned int ProcessStateChangeRequest : 2;
    unsigned int ProcessStateChangeInProgress : 1;
    unsigned int DisallowWin32kSystemCalls : 1;
} EPROCESS_FLAGS2, *PEPROCESS_FLAGS2;

typedef struct _MITIGATION_FLAGS
{
    unsigned int ControlFlowGuardEnabled : 1;
    unsigned int ControlFlowGuardExportSuppressionEnabled : 1;
    unsigned int ControlFlowGuardStrict : 1;
    unsigned int DisallowStrippedImages : 1;
    unsigned int ForceRelocateImages : 1;
    unsigned int HighEntropyASLREnabled : 1;
    unsigned int StackRandomizationDisabled : 1;
    unsigned int ExtensionPointDisable : 1;
    unsigned int DisableDynamicCode : 1;
    unsigned int DisableDynamicCodeAllowOptOut : 1;
    unsigned int DisableDynamicCodeAllowRemoteDowngrade : 1;
    unsigned int AuditDisableDynamicCode : 1;
    unsigned int DisallowWin32kSystemCalls : 1;
    unsigned int AuditDisallowWin32kSystemCalls : 1;
    unsigned int EnableFilteredWin32kAPIs : 1;
    unsigned int AuditFilteredWin32kAPIs : 1;
    unsigned int DisableNonSystemFonts : 1;
    unsigned int AuditNonSystemFontLoading : 1;
    unsigned int PreferSystem32Images : 1;
    unsigned int ProhibitRemoteImageMap : 1;
    unsigned int AuditProhibitRemoteImageMap : 1;
    unsigned int ProhibitLowILImageMap : 1;
    unsigned int AuditProhibitLowILImageMap : 1;
    unsigned int SignatureMitigationOpt: 1;
    unsigned int AuditBlockNonMicrosoftBinaries : 1;
    unsigned int AuditBlockNonMicrosoftBinariesAllowStore : 1;
    unsigned int LoaderIntegrityContinuityEnabled : 1;
    unsigned int AuditLoaderIntegrityContinuity : 1;
    unsigned int EnableModuleTamperingProtection : 1;
    unsigned int EnableModuleTamperingProtectionNoInherit : 1;
    unsigned int RestrictIndirectBranchPrediction;
    unsigned int IsolateSecurityDomain;
} MITIGATION_FLAGS, *PMITIGATION_FLAGS;

typedef union _EXHANDLE
{
    struct
    {
        int TagBits : 2;
        int Index : 30;
    } u;
    void * GenericHandleOverlay;
    ULONG_PTR Value;
} EXHANDLE, *PEXHANDLE;

#pragma warning(disable : 4214 4201)

#pragma pack(push, 1)
typedef struct _POOL_HEADER // Size=16
{
    union
    {
        struct
        {
            unsigned long PreviousSize : 8; // Size=4 Offset=0 BitOffset=0 BitCount=8
            unsigned long PoolIndex : 8; // Size=4 Offset=0 BitOffset=8 BitCount=8
            unsigned long BlockSize : 8; // Size=4 Offset=0 BitOffset=16 BitCount=8
            unsigned long PoolType : 8; // Size=4 Offset=0 BitOffset=24 BitCount=8
        };
        unsigned long Ulong1; // Size=4 Offset=0
    };
    unsigned long PoolTag; // Size=4 Offset=4
    union
    {
        struct _EPROCESS * ProcessBilled; // Size=8 Offset=8
        struct
        {
            unsigned short AllocatorBackTraceIndex; // Size=2 Offset=8
            unsigned short PoolTagHash; // Size=2 Offset=10
        };
    };
} POOL_HEADER, *PPOOL_HEADER;
#pragma pack(pop)

typedef struct _HANDLE_TABLE_ENTRY // Size=16
{
    union
    {
        ULONG_PTR VolatileLowValue; // Size=8 Offset=0
        ULONG_PTR LowValue; // Size=8 Offset=0
        struct _HANDLE_TABLE_ENTRY_INFO * InfoTable; // Size=8 Offset=0
        struct
        {
            ULONG_PTR Unlocked : 1; // Size=8 Offset=0 BitOffset=0 BitCount=1
            ULONG_PTR RefCnt : 16; // Size=8 Offset=0 BitOffset=1 BitCount=16
            ULONG_PTR Attributes : 3; // Size=8 Offset=0 BitOffset=17 BitCount=3
            ULONG_PTR ObjectPointerBits : 44; // Size=8 Offset=0 BitOffset=20 BitCount=44
        };
    };
    union
    {
        ULONG_PTR HighValue; // Size=8 Offset=8
        struct _HANDLE_TABLE_ENTRY * NextFreeHandleEntry; // Size=8 Offset=8
        union _EXHANDLE LeafHandleValue; // Size=8 Offset=8
        struct
        {
            ULONG GrantedAccessBits : 25; // Size=4 Offset=8 BitOffset=0 BitCount=25
            ULONG NoRightsUpgrade : 1; // Size=4 Offset=8 BitOffset=25 BitCount=1
            ULONG Spare : 6; // Size=4 Offset=8 BitOffset=26 BitCount=6
        };
    };
    ULONG TypeInfo; // Size=4 Offset=12
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;



typedef struct _OBJECT_HEADER // Size=56
{
    ULONG_PTR PointerCount; // Size=8 Offset=0
    union
    {
        ULONG_PTR HandleCount; // Size=8 Offset=8
        void * NextToFree; // Size=8 Offset=8
    };
    void* Lock; // Size=8 Offset=16
    UCHAR TypeIndex; // Size=1 Offset=24
    union
    {
        UCHAR TraceFlags; // Size=1 Offset=25
        struct
        {
            UCHAR DbgRefTrace : 1; // Size=1 Offset=25 BitOffset=0 BitCount=1
            UCHAR DbgTracePermanent : 1; // Size=1 Offset=25 BitOffset=1 BitCount=1
        };
    };
    UCHAR InfoMask; // Size=1 Offset=26
    union
    {
        UCHAR Flags; // Size=1 Offset=27
        struct
        {
            UCHAR NewObject : 1; // Size=1 Offset=27 BitOffset=0 BitCount=1
            UCHAR KernelObject : 1; // Size=1 Offset=27 BitOffset=1 BitCount=1
            UCHAR KernelOnlyAccess : 1; // Size=1 Offset=27 BitOffset=2 BitCount=1
            UCHAR ExclusiveObject : 1; // Size=1 Offset=27 BitOffset=3 BitCount=1
            UCHAR PermanentObject : 1; // Size=1 Offset=27 BitOffset=4 BitCount=1
            UCHAR DefaultSecurityQuota : 1; // Size=1 Offset=27 BitOffset=5 BitCount=1
            UCHAR SingleHandleEntry : 1; // Size=1 Offset=27 BitOffset=6 BitCount=1
            UCHAR DeletedInline : 1; // Size=1 Offset=27 BitOffset=7 BitCount=1
        };
    };
    ULONG Spare; // Size=4 Offset=28
    union
    {
        struct _OBJECT_CREATE_INFORMATION * ObjectCreateInfo; // Size=8 Offset=32
        void * QuotaBlockCharged; // Size=8 Offset=32
    };
    void * SecurityDescriptor; // Size=8 Offset=40
    struct _QUAD Body; // Size=8 Offset=48
} OBJECT_HEADER, *POBJECT_HEADER;

typedef union _EX_FAST_REF // Size=8
{
    void * Object;
    struct
    {
        unsigned __int64 RefCnt : 4; 
    };
    unsigned __int64 Value;
} EX_FAST_REF, *PEX_FAST_REF;

typedef struct _CONTROL_AREA // Size=120
{
    struct _SEGMENT * Segment;
    struct _LIST_ENTRY ListHead;
    unsigned __int64 NumberOfSectionReferences;
    unsigned __int64 NumberOfPfnReferences; 
    unsigned __int64 NumberOfMappedViews;
    unsigned __int64 NumberOfUserReferences;
    unsigned long f1; 
    unsigned long f2;
    EX_FAST_REF FilePointer;
    // Other fields
} CONTROL_AREA, *PCONTROL_AREA;

typedef struct _SUBSECTION // Size=56
{
    PCONTROL_AREA ControlArea;
    // Other fields
} SUBSECTION, *PSUBSECTION;

typedef struct _MEMORY_BASIC_INFORMATION_EX
{
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} MEMORY_BASIC_INFORMATION_EX, *PMEMORY_BASIC_INFORMATION_EX;

typedef struct _SYSTEM_CALL_COUNT_INFORMATION
{
    ULONG Length;
    ULONG NumberOfTables;
    ULONG limits[2];
 } SYSTEM_CALL_COUNT_INFORMATION, *PSYSTEM_CALL_COUNT_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PVOID TeUNIaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

#pragma warning(disable : 4214)
typedef struct _MMPTE_HARDWARE64
{
    ULONGLONG Valid : 1;
    ULONGLONG Dirty1 : 1;
    ULONGLONG Owner : 1;
    ULONGLONG WriteThrough : 1;
    ULONGLONG CacheDisable : 1;
    ULONGLONG Accessed : 1;
    ULONGLONG Dirty : 1;
    ULONGLONG LargePage : 1;
    ULONGLONG Global : 1;
    ULONGLONG CopyOnWrite : 1;
    ULONGLONG Unused : 1;
    ULONGLONG Write : 1;
    ULONGLONG PageFrameNumber : 36;
    ULONGLONG reserved1 : 4;
    ULONGLONG SoftwareWsIndex : 11;
    ULONGLONG NoExecute : 1;
} MMPTE_HARDWARE64, *PMMPTE_HARDWARE64;

typedef struct _MMPTE 
{
    union  
    {
        ULONG_PTR Long;
        MMPTE_HARDWARE64 Hard;
    } u;
} MMPTE;
typedef MMPTE *PMMPTE;

#pragma warning(default : 4214)

typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY
{
    ULONG Attribute;    // PROC_THREAD_ATTRIBUTE_XXX
    SIZE_T Size;
    ULONG_PTR Value;
    ULONG Unknown;
} NT_PROC_THREAD_ATTRIBUTE_ENTRY, *NT_PPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST
{
    ULONG Length;
    NT_PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
} NT_PROC_THREAD_ATTRIBUTE_LIST, *PNT_PROC_THREAD_ATTRIBUTE_LIST;


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;         // Not filled in
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#pragma warning(disable : 4214)
typedef union _MEMORY_WORKING_SET_EX_BLOCK 
{
    ULONG_PTR Flags;
    struct
    {
        ULONG_PTR Valid : 1;
        ULONG_PTR ShareCount : 3;
        ULONG_PTR Win32Protection : 11;
        ULONG_PTR Shared : 1;
        ULONG_PTR Node : 6;
        ULONG_PTR Locked : 1;
        ULONG_PTR LargePage : 1;
        ULONG_PTR Reserved : 7;
        ULONG_PTR Bad : 1;

#if defined(_WIN64)
        ULONG_PTR ReservedUlong : 32;
#endif
    };
} MEMORY_WORKING_SET_EX_BLOCK, *PMEMORY_WORKING_SET_EX_BLOCK;

typedef struct _MEMORY_WORKING_SET_EX_INFORMATION 
{
    PVOID VirtualAddress;
    MEMORY_WORKING_SET_EX_BLOCK VirtualAttributes;
} MEMORY_WORKING_SET_EX_INFORMATION, *PMEMORY_WORKING_SET_EX_INFORMATION;

#pragma warning(default : 4214)


typedef struct _PEB_LDR_DATA 
{
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY 
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB 
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    PVOID CrossProcessFlags;
    PVOID KernelCallbackTable;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
} PEB, *PPEB;

typedef struct _PEB_LDR_DATA32
{
    ULONG Length;
    UCHAR Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY32 HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB32
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG Ldr;
    ULONG ProcessParameters;
    ULONG SubSystemData;
    ULONG ProcessHeap;
    ULONG FastPebLock;
    ULONG AtlThunkSListPtr;
    ULONG IFEOKey;
    ULONG CrossProcessFlags;
    ULONG UserSharedInfoPtr;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    ULONG ApiSetMap;
} PEB32, *PPEB32;

typedef struct _WOW64_PROCESS 
{
    PPEB32 Wow64;
} WOW64_PROCESS, *PWOW64_PROCESS;

typedef union _WOW64_APC_CONTEXT 
{
    struct 
    {
        ULONG Apc32BitContext;
        ULONG Apc32BitRoutine;
    };

    PVOID Apc64BitContext;

} WOW64_APC_CONTEXT, *PWOW64_APC_CONTEXT;

typedef struct _NON_PAGED_DEBUG_INFO
{
    USHORT      Signature;
    USHORT      Flags;
    ULONG       Size;
    USHORT      Machine;
    USHORT      Characteristics;
    ULONG       TimeDateStamp;
    ULONG       CheckSum;
    ULONG       SizeOfImage;
    ULONGLONG   ImageBase;
} NON_PAGED_DEBUG_INFO, *PNON_PAGED_DEBUG_INFO;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    // ULONG padding on IA64
    PVOID GpValue;
    PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5;
    PVOID SectionPointer;
    ULONG CheckSum;
    // ULONG padding on IA64
    PVOID LoadedImports;
    PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;


//
// This structure is used by the debugger for all targets
// It is the same size as DBGKD_DATA_HEADER on all systems
//
typedef struct _DBGKD_DEBUG_DATA_HEADER64 {

    //
    // Link to other blocks
    //

    LIST_ENTRY64 List;

    //
    // This is a unique tag to identify the owner of the block.
    // If your component only uses one pool tag, use it for this, too.
    //

    ULONG           OwnerTag;

    //
    // This must be initialized to the size of the data block,
    // including this structure.
    //

    ULONG           Size;

} DBGKD_DEBUG_DATA_HEADER64, *PDBGKD_DEBUG_DATA_HEADER64;


//
// This structure is the same size on all systems.  The only field
// which must be translated by the debugger is Header.List.
//

//
// DO NOT ADD OR REMOVE FIELDS FROM THE MIDDLE OF THIS STRUCTURE!!!
//
// If you remove a field, replace it with an "unused" placeholder.
// Do not reuse fields until there has been enough time for old debuggers
// and extensions to age out.
//
typedef struct _KDDEBUGGER_DATA64 {

    DBGKD_DEBUG_DATA_HEADER64 Header;

    //
    // Base address of kernel image
    //

    ULONG64   KernBase;

    //
    // DbgBreakPointWithStatus is a function which takes an argument
    // and hits a breakpoint.  This field contains the address of the
    // breakpoint instruction.  When the debugger sees a breakpoint
    // at this address, it may retrieve the argument from the first
    // argument register, or on x86 the eax register.
    //

    ULONG64   BreakpointWithStatus;       // address of breakpoint

    //
    // Address of the saved context record during a bugcheck
    //
    // N.B. This is an automatic KeBugcheckEx's frame, and
    // is only valid after a bugcheck.
    //

    ULONG64   SavedContext;

    //
    // help for walking stacks with user callbacks:
    //

    //
    // The address of the thread structure is provided the
    // WAIT_STATE_CHANGE packet.  This is the offset from the base of
    // the thread structure to the pointer to the kernel stack frame
    // for the currently active usermode callback.
    //

    USHORT  ThCallbackStack;            // offset thread data

    //
    // these values are offsets into that frame:
    //

    USHORT  NextCallback;               // saved pointer to next callback frame
    USHORT  FramePointer;               // saved frame pointer

    //
    // pad to a quad boundary
    //
    USHORT  PaeEnabled;

    //
    // Address of the kernel callout routine.
    //

    ULONG64   KiCallUserMode;             // kernel routine

    //
    // Address of the usermode entry point for callbacks.
    //

    ULONG64   KeUserCallbackDispatcher;   // address ntdll


    //
    // Addresses of various kernel data structures and lists
    // that are of interest to the kernel debugger.
    //

    ULONG64   PsLoadedModuleList;
    ULONG64   PsActiveProcessHead;
    ULONG64   PspCidTable;

    ULONG64   ExpSystemResourcesList;
    ULONG64   ExpPagedPoolDescriptor;
    ULONG64   ExpNumberOfPagedPools;

    ULONG64   KeTimeIncrement;
    ULONG64   KeBugCheckCallbackListHead;
    ULONG64   KiBugcheckData;

    ULONG64   IopErrorLogListHead;

    ULONG64   ObpRootDirectoryObject;
    ULONG64   ObpTypeObjectType;

    ULONG64   MmSystemCacheStart;
    ULONG64   MmSystemCacheEnd;
    ULONG64   MmSystemCacheWs;

    ULONG64   MmPfnDatabase;
    ULONG64   MmSystemPtesStart;
    ULONG64   MmSystemPtesEnd;
    ULONG64   MmSubsectionBase;
    ULONG64   MmNumberOfPagingFiles;

    ULONG64   MmLowestPhysicalPage;
    ULONG64   MmHighestPhysicalPage;
    ULONG64   MmNumberOfPhysicalPages;

    ULONG64   MmMaximumNonPagedPoolInBytes;
    ULONG64   MmNonPagedSystemStart;
    ULONG64   MmNonPagedPoolStart;
    ULONG64   MmNonPagedPoolEnd;

    ULONG64   MmPagedPoolStart;
    ULONG64   MmPagedPoolEnd;
    ULONG64   MmPagedPoolInformation;
    ULONG64   MmPageSize;

    ULONG64   MmSizeOfPagedPoolInBytes;

    ULONG64   MmTotalCommitLimit;
    ULONG64   MmTotalCommittedPages;
    ULONG64   MmSharedCommit;
    ULONG64   MmDriverCommit;
    ULONG64   MmProcessCommit;
    ULONG64   MmPagedPoolCommit;
    ULONG64   MmExtendedCommit;

    ULONG64   MmZeroedPageListHead;
    ULONG64   MmFreePageListHead;
    ULONG64   MmStandbyPageListHead;
    ULONG64   MmModifiedPageListHead;
    ULONG64   MmModifiedNoWritePageListHead;
    ULONG64   MmAvailablePages;
    ULONG64   MmResidentAvailablePages;

    ULONG64   PoolTrackTable;
    ULONG64   NonPagedPoolDescriptor;

    ULONG64   MmHighestUserAddress;
    ULONG64   MmSystemRangeStart;
    ULONG64   MmUserProbeAddress;

    ULONG64   KdPrintCircularBuffer;
    ULONG64   KdPrintCircularBufferEnd;
    ULONG64   KdPrintWritePointer;
    ULONG64   KdPrintRolloverCount;

    ULONG64   MmLoadedUserImageList;

    // NT 5.1 Addition

    ULONG64   NtBuildLab;
    ULONG64   KiNormalSystemCall;

    // NT 5.0 hotfix addition

    ULONG64   KiProcessorBlock;
    ULONG64   MmUnloadedDrivers;
    ULONG64   MmLastUnloadedDriver;
    ULONG64   MmTriageActionTaken;
    ULONG64   MmSpecialPoolTag;
    ULONG64   KernelVerifier;
    ULONG64   MmVerifierData;
    ULONG64   MmAllocatedNonPagedPool;
    ULONG64   MmPeakCommitment;
    ULONG64   MmTotalCommitLimitMaximum;
    ULONG64   CmNtCSDVersion;

    // NT 5.1 Addition

    ULONG64   MmPhysicalMemoryBlock;
    ULONG64   MmSessionBase;
    ULONG64   MmSessionSize;
    ULONG64   MmSystemParentTablePage;

    // Server 2003 addition

    ULONG64   MmVirtualTranslationBase;

    USHORT    OffsetKThreadNextProcessor;
    USHORT    OffsetKThreadTeb;
    USHORT    OffsetKThreadKernelStack;
    USHORT    OffsetKThreadInitialStack;

    USHORT    OffsetKThreadApcProcess;
    USHORT    OffsetKThreadState;
    USHORT    OffsetKThreadBStore;
    USHORT    OffsetKThreadBStoreLimit;

    USHORT    SizeEProcess;
    USHORT    OffsetEprocessPeb;
    USHORT    OffsetEprocessParentCID;
    USHORT    OffsetEprocessDirectoryTableBase;

    USHORT    SizePrcb;
    USHORT    OffsetPrcbDpcRoutine;
    USHORT    OffsetPrcbCurrentThread;
    USHORT    OffsetPrcbMhz;

    USHORT    OffsetPrcbCpuType;
    USHORT    OffsetPrcbVendorString;
    USHORT    OffsetPrcbProcStateContext;
    USHORT    OffsetPrcbNumber;

    USHORT    SizeEThread;

    ULONG64   KdPrintCircularBufferPtr;
    ULONG64   KdPrintBufferSize;

    ULONG64   KeLoaderBlock;

    USHORT    SizePcr;
    USHORT    OffsetPcrSelfPcr;
    USHORT    OffsetPcrCurrentPrcb;
    USHORT    OffsetPcrContainedPrcb;

    USHORT    OffsetPcrInitialBStore;
    USHORT    OffsetPcrBStoreLimit;
    USHORT    OffsetPcrInitialStack;
    USHORT    OffsetPcrStackLimit;

    USHORT    OffsetPrcbPcrPage;
    USHORT    OffsetPrcbProcStateSpecialReg;
    USHORT    GdtR0Code;
    USHORT    GdtR0Data;

    USHORT    GdtR0Pcr;
    USHORT    GdtR3Code;
    USHORT    GdtR3Data;
    USHORT    GdtR3Teb;

    USHORT    GdtLdt;
    USHORT    GdtTss;
    USHORT    Gdt64R3CmCode;
    USHORT    Gdt64R3CmTeb;

    ULONG64   IopNumTriageDumpDataBlocks;
    ULONG64   IopTriageDumpDataBlocks;

    // Longhorn addition

    ULONG64   VfCrashDataBlock;
    ULONG64   MmBadPagesDetected;
    ULONG64   MmZeroedPageSingleBitErrorsDetected;

    // Windows 7 addition

    ULONG64   EtwpDebuggerData;
    USHORT    OffsetPrcbContext;

    // Windows 8 addition

    USHORT    OffsetPrcbMaxBreakpoints;
    USHORT    OffsetPrcbMaxWatchpoints;

    ULONG     OffsetKThreadStackLimit;
    ULONG     OffsetKThreadStackBase;
    ULONG     OffsetKThreadQueueListEntry;
    ULONG     OffsetEThreadIrpList;

    USHORT    OffsetPrcbIdleThread;
    USHORT    OffsetPrcbNormalDpcState;
    USHORT    OffsetPrcbDpcStack;
    USHORT    OffsetPrcbIsrStack;

    USHORT    SizeKDPC_STACK_FRAME;

    // Windows 8.1 Addition

    USHORT    OffsetKPriQueueThreadListHead;
    USHORT    OffsetKThreadWaitReason;

    // Windows 10 RS1 Addition

    USHORT    Padding;
    ULONG64   PteBase;

    // Windows 10 RS5 Addition

    ULONG64 RetpolineStubFunctionTable;
    ULONG RetpolineStubFunctionTableSize;
    ULONG RetpolineStubOffset;
    ULONG RetpolineStubSize;

} KDDEBUGGER_DATA64, *PKDDEBUGGER_DATA64;


typedef struct _DUMP_HEADER
{
    ULONG Signature;
    ULONG ValidDump;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG_PTR DirectoryTableBase;
    ULONG_PTR PfnDataBase;
    PLIST_ENTRY PsLoadedModuleList;
    PLIST_ENTRY PsActiveProcessHead;
    ULONG MachineImageType;
    ULONG NumberProcessors;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParameter1;
    ULONG_PTR BugCheckParameter2;
    ULONG_PTR BugCheckParameter3;
    ULONG_PTR BugCheckParameter4;
    CHAR VersionUser[32];
    struct _KDDEBUGGER_DATA64 *KdDebuggerDataBlock;
} DUMP_HEADER, *PDUMP_HEADER;

extern KDDEBUGGER_DATA64 g_KdBlock;